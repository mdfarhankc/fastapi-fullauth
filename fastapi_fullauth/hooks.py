from collections.abc import Awaitable, Callable
from typing import Any

# Hook type: async def hook(user: UserSchema, **kwargs) -> None
EventHook = Callable[..., Awaitable[Any]]


class EventHooks:
    """Registry for lifecycle event callbacks."""

    def __init__(self) -> None:
        self._hooks: dict[str, list[EventHook]] = {}

    def on(self, event: str, callback: EventHook) -> None:
        self._hooks.setdefault(event, []).append(callback)

    async def emit(self, event: str, **kwargs: Any) -> None:
        for hook in self._hooks.get(event, []):
            await hook(**kwargs)

    # --- Supported events ---
    # "after_register"              -> (user: UserSchema)
    # "after_login"                 -> (user: UserSchema)
    # "after_logout"                -> (user_id: str)
    # "after_password_change"       -> (user: UserSchema)
    # "after_email_verify"          -> (user: UserSchema)
    # "after_password_reset"        -> (user: UserSchema)
    # "send_verification_email"     -> (email: str, token: str)
    # "send_password_reset_email"   -> (email: str, token: str)
