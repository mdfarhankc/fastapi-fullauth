from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, FastAPI

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import InMemoryBlacklist, TokenEngine
from fastapi_fullauth.hooks import EventHooks
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.router.auth import create_auth_router
from fastapi_fullauth.types import CreateUserSchema, UserSchema
from fastapi_fullauth.validators import PasswordValidator

# callback type: async def send_email(email: str, token: str) -> None
EmailSender = Callable[[str, str], Awaitable[Any]]

# callback type: async def claims_builder(user: UserSchema) -> dict
TokenClaimsBuilder = Callable[[UserSchema], Awaitable[dict[str, Any]]]


class FullAuth:
    def __init__(
        self,
        config: FullAuthConfig,
        adapter: AbstractUserAdapter,
        backends: list[AbstractBackend] | None = None,
        on_send_verification_email: EmailSender | None = None,
        on_send_password_reset_email: EmailSender | None = None,
        password_validator: PasswordValidator | None = None,
        enabled_routes: list[str] | None = None,
        include_user_in_login: bool = False,
        create_user_schema: type[CreateUserSchema] = CreateUserSchema,
        on_create_token_claims: TokenClaimsBuilder | None = None,
    ) -> None:
        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(
            config=config, blacklist=InMemoryBlacklist()
        )
        self.lockout = LockoutManager(
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )
        self.on_send_verification_email = on_send_verification_email
        self.on_send_password_reset_email = on_send_password_reset_email
        self.password_validator = password_validator or PasswordValidator(
            min_length=config.PASSWORD_MIN_LENGTH
        )
        self.include_user_in_login = include_user_in_login
        self.create_user_schema = create_user_schema
        self.on_create_token_claims = on_create_token_claims
        self.hooks = EventHooks()

        # routes that will be included — None means all
        self._enabled_routes = set(enabled_routes) if enabled_routes else None
        self._router: APIRouter | None = None

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

    def init_app(self, app: FastAPI) -> None:
        from fastapi_fullauth.dependencies.current_user import configure_oauth2_scheme

        prefix = self.config.API_PREFIX.rstrip("/") + self.config.AUTH_ROUTER_PREFIX
        configure_oauth2_scheme(f"{prefix}/login")

        app.state.fullauth = self
        app.include_router(self.router)
