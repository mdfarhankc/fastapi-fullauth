from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, FastAPI

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import InMemoryBlacklist, TokenBlacklist, TokenEngine
from fastapi_fullauth.hooks import EventHooks
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.protection.ratelimit import RateLimiter
from fastapi_fullauth.router.auth import create_auth_router
from fastapi_fullauth.types import CreateUserSchema, Route, UserSchema
from fastapi_fullauth.validators import PasswordValidator

EmailSender = Callable[[str, str], Awaitable[Any]]
TokenClaimsBuilder = Callable[[UserSchema], Awaitable[dict[str, Any]]]


class FullAuth:
    def __init__(
        self,
        config: FullAuthConfig | None = None,
        *,
        adapter: AbstractUserAdapter,
        secret_key: str | None = None,
        backends: list[AbstractBackend] | None = None,
        on_send_verification_email: EmailSender | None = None,
        on_send_password_reset_email: EmailSender | None = None,
        password_validator: PasswordValidator | None = None,
        enabled_routes: list[str | Route] | None = None,
        include_user_in_login: bool = False,
        create_user_schema: type[CreateUserSchema] | None = None,
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

        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(config=config, blacklist=self._create_blacklist(config))
        self.lockout = LockoutManager(
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )

        self.auth_rate_limiters: dict[str, RateLimiter] = {}
        if config.AUTH_RATE_LIMIT_ENABLED:
            window = config.AUTH_RATE_LIMIT_WINDOW_SECONDS
            self.auth_rate_limiters["login"] = RateLimiter(config.AUTH_RATE_LIMIT_LOGIN, window)
            self.auth_rate_limiters["register"] = RateLimiter(
                config.AUTH_RATE_LIMIT_REGISTER, window
            )
            self.auth_rate_limiters["password-reset"] = RateLimiter(
                config.AUTH_RATE_LIMIT_PASSWORD_RESET, window
            )

        self.on_send_verification_email = on_send_verification_email
        self.on_send_password_reset_email = on_send_password_reset_email
        self.password_validator = password_validator or PasswordValidator(
            min_length=config.PASSWORD_MIN_LENGTH
        )
        self.include_user_in_login = include_user_in_login
        self.create_user_schema = create_user_schema or self._resolve_create_schema(adapter)
        self.on_create_token_claims = on_create_token_claims
        self.hooks = EventHooks()

        if on_send_verification_email:
            self.hooks.on("send_verification_email", on_send_verification_email)
        if on_send_password_reset_email:
            self.hooks.on("send_password_reset_email", on_send_password_reset_email)

        self._enabled_routes = set(enabled_routes) if enabled_routes else None
        self._router: APIRouter | None = None

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

    @staticmethod
    def _resolve_create_schema(adapter: AbstractUserAdapter) -> type[CreateUserSchema]:
        user_model = getattr(adapter, "_user_model", None)
        if user_model is None:
            return CreateUserSchema

        model_fields = getattr(user_model, "model_fields", None)
        if model_fields is None:
            return CreateUserSchema

        from pydantic import create_model

        skip = {
            "id",
            "hashed_password",
            "created_at",
            "is_active",
            "is_verified",
            "is_superuser",
            "roles",
            "refresh_tokens",
        }
        base_fields = set(CreateUserSchema.model_fields.keys())
        extra: dict[str, Any] = {}
        for name, field in model_fields.items():
            if name in base_fields or name in skip:
                continue
            default = field.default if field.default is not None else None
            extra[name] = (field.annotation | None, default)
        if not extra:
            return CreateUserSchema
        return create_model("DerivedCreateUserSchema", __base__=CreateUserSchema, **extra)

    def check_auth_rate_limit(self, route_name: str, client_ip: str) -> None:
        limiter = self.auth_rate_limiters.get(route_name)
        if limiter and not limiter.is_allowed(client_ip):
            from fastapi import HTTPException

            raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    def is_route_enabled(self, route_name: str) -> bool:
        if self._enabled_routes is None:
            return True
        return route_name in self._enabled_routes

    @property
    def router(self) -> APIRouter:
        if self._router is None:
            prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
            self._router = APIRouter(prefix=prefix, tags=self.config.ROUTER_TAGS)
            self._router.include_router(
                create_auth_router(create_user_schema=self.create_user_schema)
            )
        return self._router

    def init_app(self, app: FastAPI, *, auto_middleware: bool = True) -> None:
        from fastapi_fullauth.dependencies.current_user import configure_oauth2_scheme

        prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
        configure_oauth2_scheme(f"{prefix}/login")

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

            app.add_middleware(RateLimitMiddleware)

        if self.config.INJECT_SECURITY_HEADERS:
            from fastapi_fullauth.middleware.security_headers import (
                SecurityHeadersMiddleware,
            )

            app.add_middleware(SecurityHeadersMiddleware)
