from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, FastAPI

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import InMemoryBlacklist, TokenEngine
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.router.auth import create_auth_router

# callback type: async def send_email(email: str, token: str) -> None
EmailSender = Callable[[str, str], Awaitable[Any]]


class FullAuth:
    def __init__(
        self,
        config: FullAuthConfig,
        adapter: AbstractUserAdapter,
        backends: list[AbstractBackend] | None = None,
        on_send_verification_email: EmailSender | None = None,
    ) -> None:
        self.config = config
        self.adapter = adapter
        self.backends = backends or [BearerBackend()]
        self.token_engine = TokenEngine(
            config=config, blacklist=InMemoryBlacklist())
        self.lockout = LockoutManager(
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )
        self.on_send_verification_email = on_send_verification_email
        self._router: APIRouter | None = None

    @property
    def router(self) -> APIRouter:
        if self._router is None:
            self._router = APIRouter(prefix=self.config.AUTH_ROUTER_PREFIX)
            self._router.include_router(create_auth_router())
        return self._router

    def init_app(self, app: FastAPI) -> None:
        app.state.fullauth = self
        app.include_router(self.router)
