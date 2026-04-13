from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol, overload

from fastapi_fullauth.types import UserID, UserSchema


class AfterUserHook(Protocol):
    async def __call__(self, user: UserSchema) -> Any: ...


class AfterLogoutHook(Protocol):
    async def __call__(self, user_id: UserID) -> Any: ...


class EmailHook(Protocol):
    async def __call__(self, email: str, token: str) -> Any: ...


EventHook = Callable[..., Awaitable[Any]]


class EventHooks:
    def __init__(self) -> None:
        self._hooks: dict[str, list[EventHook]] = {}

    @overload
    def on(self, event: Literal["after_register"], callback: AfterUserHook) -> None: ...
    @overload
    def on(self, event: Literal["after_login"], callback: AfterUserHook) -> None: ...
    @overload
    def on(self, event: Literal["after_logout"], callback: AfterLogoutHook) -> None: ...
    @overload
    def on(self, event: Literal["after_password_change"], callback: AfterUserHook) -> None: ...
    @overload
    def on(self, event: Literal["after_password_reset"], callback: AfterUserHook) -> None: ...
    @overload
    def on(self, event: Literal["after_email_verify"], callback: AfterUserHook) -> None: ...
    @overload
    def on(self, event: Literal["send_verification_email"], callback: EmailHook) -> None: ...
    @overload
    def on(self, event: Literal["send_password_reset_email"], callback: EmailHook) -> None: ...
    @overload
    def on(self, event: str, callback: EventHook) -> None: ...

    def on(self, event: str, callback: EventHook) -> None:
        self._hooks.setdefault(event, []).append(callback)

    async def emit(self, event: str, **kwargs: Any) -> None:
        for hook in self._hooks.get(event, []):
            await hook(**kwargs)
