import logging
from collections.abc import Awaitable, Callable
from typing import Any, Generic

from fastapi import APIRouter, FastAPI

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.backends import AbstractBackend, BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import TokenEngine, create_blacklist
from fastapi_fullauth.hooks import EventHooks
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.protection.ratelimit import RateLimiter, RedisRateLimiter, create_rate_limiter
from fastapi_fullauth.types import CreateUserSchemaType, UserSchema, UserSchemaType
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth")

TokenClaimsBuilder = Callable[[UserSchema], Awaitable[dict[str, Any]]]


class FullAuth(Generic[UserSchemaType, CreateUserSchemaType]):
    """Main auth manager.

    Args:
        adapter: Database backend (SQLModelAdapter, SQLAlchemyAdapter, etc.).
        config: FullAuthConfig object. Reads from env (FULLAUTH_ prefix) if omitted.
        providers: OAuth providers (GoogleOAuthProvider, GitHubOAuthProvider, etc.).
        backends: Token transport strategies. Defaults to [BearerBackend()].
        password_validator: Custom PasswordValidator. Defaults to min-length from config.
        include_user_in_login: Include user data in login response.
        on_create_token_claims: async def cb(user) -> dict — extra claims embedded in JWTs.
    """

    def __init__(
        self,
        *,
        adapter: AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
        config: FullAuthConfig | None = None,
        providers: list[OAuthProvider] | None = None,
        backends: list[AbstractBackend] | None = None,
        password_validator: PasswordValidator | None = None,
        include_user_in_login: bool = False,
        on_create_token_claims: TokenClaimsBuilder | None = None,
    ) -> None:
        if config is None:
            config = FullAuthConfig()

        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(config=config, blacklist=create_blacklist(config))
        self.lockout = LockoutManager(
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )

        self.auth_rate_limiters: dict[str, RateLimiter | RedisRateLimiter] = {}
        if config.AUTH_RATE_LIMIT_ENABLED:
            window = config.AUTH_RATE_LIMIT_WINDOW_SECONDS
            self.auth_rate_limiters["login"] = create_rate_limiter(
                config, config.AUTH_RATE_LIMIT_LOGIN, window
            )
            self.auth_rate_limiters["register"] = create_rate_limiter(
                config, config.AUTH_RATE_LIMIT_REGISTER, window
            )
            self.auth_rate_limiters["password-reset"] = create_rate_limiter(
                config, config.AUTH_RATE_LIMIT_PASSWORD_RESET, window
            )

        self.password_validator = password_validator or PasswordValidator(
            min_length=config.PASSWORD_MIN_LENGTH
        )
        self.include_user_in_login = include_user_in_login
        self.on_create_token_claims = on_create_token_claims
        self.hooks = EventHooks()
        self.oauth_providers: dict[str, OAuthProvider] = {p.name: p for p in (providers or [])}

        self._auth_router: APIRouter | None = None
        self._profile_router: APIRouter | None = None
        self._verify_router: APIRouter | None = None
        self._admin_router: APIRouter | None = None
        self._router: APIRouter | None = None

    _RESERVED_CLAIM_KEYS = frozenset(
        {"sub", "exp", "iat", "jti", "type", "roles", "extra", "family_id"}
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

    # ── composable routers ──────────────────────────────────────────

    @property
    def auth_router(self) -> APIRouter:
        if self._auth_router is None:
            from fastapi_fullauth.router.auth import create_auth_router

            self._auth_router = create_auth_router(
                create_user_schema=self.adapter._create_user_schema,
                user_schema=self.adapter._user_schema,
                login_field=self.config.LOGIN_FIELD,
            )
        return self._auth_router

    @property
    def profile_router(self) -> APIRouter:
        if self._profile_router is None:
            from fastapi_fullauth.router.profile import create_profile_router

            self._profile_router = create_profile_router(
                user_schema=self.adapter._user_schema,
            )
        return self._profile_router

    @property
    def verify_router(self) -> APIRouter:
        if self._verify_router is None:
            from fastapi_fullauth.router.verify import create_verify_router

            self._verify_router = create_verify_router()
        return self._verify_router

    @property
    def admin_router(self) -> APIRouter:
        if self._admin_router is None:
            from fastapi_fullauth.router.admin import create_admin_router

            self._admin_router = create_admin_router()
        return self._admin_router

    @property
    def oauth_router(self) -> APIRouter | None:
        if not self.oauth_providers:
            return None
        from fastapi_fullauth.router.oauth import create_oauth_router

        return create_oauth_router()

    @property
    def router(self) -> APIRouter:
        """Combined router with all route groups. Used by init_app()."""
        if self._router is None:
            prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
            self._router = APIRouter(prefix=prefix, tags=self.config.ROUTER_TAGS)
            self._router.include_router(self.auth_router)
            self._router.include_router(self.profile_router)
            self._router.include_router(self.verify_router)
            self._router.include_router(self.admin_router)
            if self.oauth_router is not None:
                self._router.include_router(self.oauth_router)
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

            middleware_limiter = create_rate_limiter(self.config, 60, 60)
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
