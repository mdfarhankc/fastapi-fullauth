import logging
from collections.abc import Awaitable, Callable
from typing import Any, Generic

from fastapi import APIRouter, FastAPI

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import InMemoryBlacklist, TokenBlacklist, TokenEngine
from fastapi_fullauth.hooks import EventHooks
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.protection.ratelimit import RateLimiter, RedisRateLimiter
from fastapi_fullauth.router.auth import create_auth_router
from fastapi_fullauth.types import CreateUserSchemaType, RouteName, UserSchema, UserSchemaType
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth")

TokenClaimsBuilder = Callable[[UserSchema], Awaitable[dict[str, Any]]]


class FullAuth(Generic[UserSchemaType, CreateUserSchemaType]):
    """Main auth manager. Pass a config object or inline kwargs (not both).

    Args:
        config: Full FullAuthConfig object. Mutually exclusive with secret_key / **config_kwargs.
        adapter: Database backend (InMemoryAdapter, SQLModelAdapter, etc.).
        secret_key: Shortcut for config. Omit to auto-generate in dev mode.
        backends: Token transport strategies. Defaults to [BearerBackend()].
        password_validator: Custom PasswordValidator. Defaults to min-length from config.
        enabled_routes: Whitelist of routes. None = all.
        include_user_in_login: Include user data in login response.
        on_create_token_claims: async def cb(user) -> dict — extra claims embedded in JWTs.
        **config_kwargs: Any FullAuthConfig field as lowercase, e.g. api_prefix="/v2" -> API_PREFIX.
    """

    def __init__(
        self,
        config: FullAuthConfig | None = None,
        *,
        adapter: AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
        secret_key: str | None = None,
        backends: list[AbstractBackend] | None = None,
        password_validator: PasswordValidator | None = None,
        enabled_routes: list[RouteName] | None = None,
        include_user_in_login: bool = False,
        on_create_token_claims: TokenClaimsBuilder | None = None,
        **config_kwargs: Any,
    ) -> None:
        # either pass a full config object or inline kwargs, not both
        if config is not None and (secret_key is not None or config_kwargs):
            raise ValueError("Pass 'config' or inline config params (secret_key=, ...), not both.")
        if config is None:
            overrides: dict[str, Any] = {}
            if secret_key is not None:
                overrides["SECRET_KEY"] = secret_key
            # api_prefix -> API_PREFIX, etc.
            overrides.update({k.upper(): v for k, v in config_kwargs.items()})
            config = FullAuthConfig(**overrides)

        from fastapi_fullauth.core.crypto import configure_hasher

        configure_hasher(config.PASSWORD_HASH_ALGORITHM)

        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(config=config, blacklist=self._create_blacklist(config))
        self.lockout = LockoutManager(
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )

        self.auth_rate_limiters: dict[str, RateLimiter | RedisRateLimiter] = {}
        if config.AUTH_RATE_LIMIT_ENABLED:
            window = config.AUTH_RATE_LIMIT_WINDOW_SECONDS
            limiter_cls = self._create_rate_limiter
            self.auth_rate_limiters["login"] = limiter_cls(
                config, config.AUTH_RATE_LIMIT_LOGIN, window
            )
            self.auth_rate_limiters["register"] = limiter_cls(
                config, config.AUTH_RATE_LIMIT_REGISTER, window
            )
            self.auth_rate_limiters["password-reset"] = limiter_cls(
                config, config.AUTH_RATE_LIMIT_PASSWORD_RESET, window
            )

        self.password_validator = password_validator or PasswordValidator(
            min_length=config.PASSWORD_MIN_LENGTH
        )
        self.include_user_in_login = include_user_in_login
        self.on_create_token_claims = on_create_token_claims
        self.hooks = EventHooks()
        self.oauth_providers = self._build_oauth_providers(config)

        self._enabled_routes = set(enabled_routes) if enabled_routes else None
        self._router: APIRouter | None = None

    _OAUTH_PROVIDER_REGISTRY: dict[str, type] = {}

    @classmethod
    def _build_oauth_providers(cls, config: FullAuthConfig) -> dict:
        if not config.OAUTH_PROVIDERS:
            return {}

        # lazy-load registry on first use
        if not cls._OAUTH_PROVIDER_REGISTRY:
            from fastapi_fullauth.oauth.github import GitHubOAuthProvider
            from fastapi_fullauth.oauth.google import GoogleOAuthProvider

            cls._OAUTH_PROVIDER_REGISTRY = {
                "google": GoogleOAuthProvider,
                "github": GitHubOAuthProvider,
            }

        providers = {}
        for name, opts in config.OAUTH_PROVIDERS.items():
            provider_cls = cls._OAUTH_PROVIDER_REGISTRY.get(name)
            if provider_cls is None:
                raise ValueError(
                    f"Unknown OAuth provider '{name}'. "
                    f"Available: {', '.join(cls._OAUTH_PROVIDER_REGISTRY)}"
                )
            providers[name] = provider_cls(
                client_id=opts["client_id"],
                client_secret=opts["client_secret"],
                redirect_uri=opts.get("redirect_uri"),
                redirect_uris=opts.get("redirect_uris"),
                scopes=opts.get("scopes"),
            )
        return providers

    @staticmethod
    def _create_rate_limiter(
        config: FullAuthConfig, max_requests: int, window_seconds: int
    ) -> RateLimiter | RedisRateLimiter:
        if config.RATE_LIMIT_BACKEND == "redis":
            if not config.REDIS_URL:
                raise ValueError("REDIS_URL must be set when RATE_LIMIT_BACKEND='redis'")
            return RedisRateLimiter(
                redis_url=config.REDIS_URL,
                max_requests=max_requests,
                window_seconds=window_seconds,
            )
        return RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    @staticmethod
    def _create_blacklist(config: FullAuthConfig) -> TokenBlacklist:
        if config.BLACKLIST_BACKEND == "redis":
            if not config.REDIS_URL:
                raise ValueError("REDIS_URL must be set when BLACKLIST_BACKEND='redis'")
            from fastapi_fullauth.core.redis_blacklist import RedisBlacklist

            return RedisBlacklist(
                redis_url=config.REDIS_URL,
                default_ttl_seconds=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )
        return InMemoryBlacklist()

    _RESERVED_CLAIM_KEYS = frozenset(
        {
            "sub",
            "exp",
            "iat",
            "jti",
            "type",
            "roles",
            "extra",
            "family_id",
        }
    )

    async def get_custom_claims(self, user: UserSchema) -> dict:
        if not self.on_create_token_claims:
            return {}

        claims = await self.on_create_token_claims(user)

        if not isinstance(claims, dict):
            raise TypeError(
                f"on_create_token_claims must return a dict, got {type(claims).__name__}"
            )

        reserved = self._RESERVED_CLAIM_KEYS & claims.keys()
        if reserved:
            raise ValueError(f"Custom claims contain reserved keys: {', '.join(sorted(reserved))}")

        return claims

    async def check_auth_rate_limit(self, route_name: str, client_ip: str) -> None:
        limiter = self.auth_rate_limiters.get(route_name)
        if limiter and not await limiter.is_allowed(client_ip):
            from fastapi import HTTPException

            logger.warning("Auth rate limit exceeded: route=%s, ip=%s", route_name, client_ip)
            raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    @property
    def router(self) -> APIRouter:
        if self._router is None:
            prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
            self._router = APIRouter(prefix=prefix, tags=self.config.ROUTER_TAGS)
            self._router.include_router(
                create_auth_router(
                    create_user_schema=self.adapter._create_user_schema,
                    user_schema=self.adapter._user_schema,
                    login_field=self.config.LOGIN_FIELD,
                    enabled_routes=self._enabled_routes,
                )
            )
            if self.oauth_providers:
                from fastapi_fullauth.router.oauth import create_oauth_router

                self._router.include_router(create_oauth_router())
        return self._router

    def init_app(self, app: FastAPI, *, auto_middleware: bool = True) -> None:
        app.state.fullauth = self
        app.include_router(self.router)

        if not auto_middleware:
            return

        if self.config.CSRF_ENABLED:
            from fastapi_fullauth.middleware.csrf import CSRFMiddleware

            app.add_middleware(
                CSRFMiddleware,
                secret=self.config.CSRF_SECRET or self.config.SECRET_KEY,
                cookie_secure=self.config.COOKIE_SECURE,
                cookie_samesite=self.config.COOKIE_SAMESITE,
                cookie_domain=self.config.COOKIE_DOMAIN,
            )

        if self.config.RATE_LIMIT_ENABLED:
            from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware

            middleware_limiter = self._create_rate_limiter(self.config, 60, 60)
            app.add_middleware(
                RateLimitMiddleware,
                limiter=middleware_limiter,
                trusted_proxy_headers=self.config.TRUSTED_PROXY_HEADERS,
            )

        if self.config.INJECT_SECURITY_HEADERS:
            from fastapi_fullauth.middleware.security_headers import (
                SecurityHeadersMiddleware,
            )

            app.add_middleware(SecurityHeadersMiddleware)
