import logging
import warnings
from typing import Any, Generic

from fastapi import APIRouter, FastAPI, Request

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    RoleAdapterMixin,
)
from fastapi_fullauth.backends import AbstractBackend, BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import TokenEngine, create_blacklist
from fastapi_fullauth.hooks import EventHooks
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.protection.lockout import create_lockout
from fastapi_fullauth.protection.ratelimit import AuthRateLimiter
from fastapi_fullauth.types import (
    CreateUserSchemaType,
    RouterName,
    TokenClaimsBuilder,
    UserSchema,
    UserSchemaType,
)
from fastapi_fullauth.utils import get_client_ip
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth")


class FullAuth(Generic[UserSchemaType, CreateUserSchemaType]):
    """Main auth manager.

    Args:
        adapter: Database backend (SQLModelAdapter, SQLAlchemyAdapter, etc.).
        config: FullAuthConfig object. Reads from env (FULLAUTH_ prefix) if omitted.
        providers: OAuth providers (GoogleOAuthProvider, GitHubOAuthProvider, etc.).
        backends: Token transport strategies. Defaults to [BearerBackend()].
        password_validator: Custom PasswordValidator. Defaults to min-length from config.
        on_create_token_claims: async `(user) -> dict` returning extra claims for JWTs.
    """

    def __init__(
        self,
        *,
        adapter: AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
        config: FullAuthConfig | None = None,
        providers: list[OAuthProvider] | None = None,
        backends: list[AbstractBackend] | None = None,
        password_validator: PasswordValidator | None = None,
        on_create_token_claims: TokenClaimsBuilder | None = None,
    ) -> None:
        if config is None:
            config = FullAuthConfig()

        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(config=config, blacklist=create_blacklist(config))
        self.lockout = create_lockout(config)
        self.auth_rate_limiter = AuthRateLimiter(config)

        self.challenge_store = None
        if config.PASSKEY_ENABLED:
            from fastapi_fullauth.protection.challenges import create_challenge_store

            self.challenge_store = create_challenge_store(config)

        self._warn_memory_backends(config)

        self.password_validator = password_validator or PasswordValidator(
            min_length=config.PASSWORD_MIN_LENGTH
        )
        self.on_create_token_claims = on_create_token_claims
        self.hooks = EventHooks()
        self.oauth_providers: dict[str, OAuthProvider] = {p.name: p for p in (providers or [])}

        self._auth_router: APIRouter | None = None
        self._profile_router: APIRouter | None = None
        self._verify_router: APIRouter | None = None
        self._admin_router: APIRouter | None = None
        self._passkey_router: APIRouter | None = None
        self._router: APIRouter | None = None

    _RESERVED_CLAIM_KEYS = frozenset(
        {"sub", "exp", "iat", "jti", "type", "roles", "extra", "family_id"}
    )

    @staticmethod
    def _warn_memory_backends(config: FullAuthConfig) -> None:
        # Each of these stores per-process state. Under `uvicorn --workers N`
        # state isn't shared between workers: blacklisted tokens stay valid on
        # other workers, lockouts and rate limits reset per worker, and passkey
        # begin/complete can land on different workers and break the flow.
        offenders: list[str] = []
        if config.BLACKLIST_ENABLED and config.BLACKLIST_BACKEND == "memory":
            offenders.append("BLACKLIST_BACKEND")
        if config.LOCKOUT_ENABLED and config.LOCKOUT_BACKEND == "memory":
            offenders.append("LOCKOUT_BACKEND")
        if config.AUTH_RATE_LIMIT_ENABLED and config.RATE_LIMIT_BACKEND == "memory":
            offenders.append("RATE_LIMIT_BACKEND")
        if config.PASSKEY_ENABLED and config.PASSKEY_CHALLENGE_BACKEND == "memory":
            offenders.append("PASSKEY_CHALLENGE_BACKEND")

        if offenders:
            warnings.warn(
                f"In-memory backends in use: {', '.join(offenders)}. "
                "State is per-process = logout/revocation, lockouts, rate limits, and "
                "passkey flows will behave inconsistently under multi-worker deployments. "
                "Set these to 'redis' (and configure REDIS_URL) in production.",
                UserWarning,
                stacklevel=3,
            )

    async def get_custom_claims(self, user: UserSchema) -> dict[str, Any]:
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
        await self.auth_rate_limiter.check(route_name, client_ip)

    async def enforce_rate_limit(self, request: Request, route_name: str) -> None:
        """Resolve the client IP and apply the auth rate limit for ``route_name``."""
        client_ip = get_client_ip(request, self.config.TRUSTED_PROXY_HEADERS)
        await self.check_auth_rate_limit(route_name, client_ip)

    # ── composable routers ──────────────────────────────────────────

    @property
    def auth_router(self) -> APIRouter:
        if self._auth_router is None:
            from fastapi_fullauth.routers.auth import create_auth_router

            self._auth_router = create_auth_router(
                create_user_schema=self.adapter._create_user_schema,
                user_schema=self.adapter._user_schema,
                login_field=self.config.LOGIN_FIELD,
            )
        return self._auth_router

    @property
    def profile_router(self) -> APIRouter:
        if self._profile_router is None:
            from fastapi_fullauth.routers.profile import create_profile_router

            self._profile_router = create_profile_router(
                user_schema=self.adapter._user_schema,
            )
        return self._profile_router

    @property
    def verify_router(self) -> APIRouter:
        if self._verify_router is None:
            from fastapi_fullauth.routers.verify import create_verify_router

            self._verify_router = create_verify_router()
        return self._verify_router

    @property
    def admin_router(self) -> APIRouter:
        if self._admin_router is None:
            from fastapi_fullauth.routers.admin import create_admin_router

            self._admin_router = create_admin_router()
        return self._admin_router

    @property
    def oauth_router(self) -> APIRouter | None:
        if not self.oauth_providers:
            return None
        from fastapi_fullauth.routers.oauth import create_oauth_router

        return create_oauth_router(user_schema=self.adapter._user_schema)

    @property
    def passkey_router(self) -> APIRouter | None:
        if not self.config.PASSKEY_ENABLED:
            return None
        if self._passkey_router is None:
            from fastapi_fullauth.routers.passkey import create_passkey_router

            self._passkey_router = create_passkey_router(
                user_schema=self.adapter._user_schema,
            )
        return self._passkey_router

    _ROUTER_NAMES: set[RouterName] = {"auth", "profile", "verify", "admin", "oauth", "passkey"}

    def _build_router(self, exclude: set[str] | None = None) -> APIRouter:
        """Build combined router, optionally excluding named sub-routers."""
        exclude = exclude or set()
        prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
        router = APIRouter(prefix=prefix, tags=self.config.ROUTER_TAGS)  # type: ignore[arg-type]
        if "auth" not in exclude:
            router.include_router(self.auth_router)
        if "profile" not in exclude:
            router.include_router(self.profile_router)
        if "verify" not in exclude:
            router.include_router(self.verify_router)
        if "admin" not in exclude and isinstance(self.adapter, RoleAdapterMixin):
            router.include_router(self.admin_router)
        if (
            "oauth" not in exclude
            and isinstance(self.adapter, OAuthAdapterMixin)
            and self.oauth_router is not None
        ):
            router.include_router(self.oauth_router)
        if (
            "passkey" not in exclude
            and isinstance(self.adapter, PasskeyAdapterMixin)
            and self.passkey_router is not None
        ):
            router.include_router(self.passkey_router)
        return router

    @property
    def router(self) -> APIRouter:
        """Combined router with all route groups. Used by init_app()."""
        if self._router is None:
            self._router = self._build_router()
        return self._router

    def bind(self, app: FastAPI) -> None:
        """Bind this FullAuth instance to a FastAPI app.

        Required when using composable routers without init_app().
        Sets app.state.fullauth so dependencies can resolve.
        Called automatically by init_app().
        """
        app.state.fullauth = self

    def init_app(
        self,
        app: FastAPI,
        *,
        include_routers: list[RouterName] | None = None,
    ) -> None:
        """Bind FullAuth to a FastAPI app and register auth routers.

        Middleware is intentionally not wired here = import what you want from
        ``fastapi_fullauth.middleware`` and call ``app.add_middleware(...)``
        yourself.

        Args:
            app: The FastAPI application.
            include_routers: Allowlist of router names to register. ``None``
                registers every available router (default). Pass an explicit
                list (e.g. ``["auth", "profile"]``) to opt in selectively.
        """
        if getattr(app.state, "_fullauth_app_wired", False):
            warnings.warn(
                "init_app() called more than once on the same app = ignoring. "
                "Routers are already wired.",
                UserWarning,
                stacklevel=2,
            )
            return
        app.state._fullauth_app_wired = True

        self.bind(app)

        if include_routers is None:
            app.include_router(self.router)
            return

        unknown = set(include_routers) - self._ROUTER_NAMES
        if unknown:
            raise ValueError(
                f"Unknown routers: {', '.join(sorted(unknown))}. "
                f"Valid names: {', '.join(sorted(self._ROUTER_NAMES))}"
            )
        exclude: set[str] = {n for n in self._ROUTER_NAMES if n not in include_routers}
        app.include_router(self._build_router(exclude=exclude))
