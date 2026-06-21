import difflib
import inspect
import logging
import warnings
from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol, TypeVar, overload

from fastapi_fullauth.types import OAuthUserInfo, UserID, UserSchema

logger = logging.getLogger("fastapi_fullauth.hooks")


class AfterUserHook(Protocol):
    async def __call__(self, user: UserSchema) -> Any: ...


class AfterLogoutHook(Protocol):
    async def __call__(self, user_id: UserID) -> Any: ...


class EmailHook(Protocol):
    async def __call__(self, email: str, token: str) -> Any: ...


class AfterOAuthLoginHook(Protocol):
    async def __call__(self, user: UserSchema, provider: str, is_new_user: bool) -> Any: ...


class AfterOAuthRegisterHook(Protocol):
    async def __call__(self, user: UserSchema, user_info: OAuthUserInfo) -> Any: ...


EventHook = Callable[..., Awaitable[Any]]
F = TypeVar("F", bound=EventHook)

# The built-in events and the keyword arguments emit() calls each hook with.
# Used to catch typos and wrong-signature callbacks at registration time.
EVENT_PARAMS: dict[str, tuple[str, ...]] = {
    "after_register": ("user",),
    "after_login": ("user",),
    "after_logout": ("user_id",),
    "after_password_change": ("user",),
    "after_password_reset": ("user",),
    "after_email_verify": ("user",),
    "after_oauth_login": ("user", "provider", "is_new_user"),
    "after_oauth_register": ("user", "user_info"),
    "send_verification_email": ("email", "token"),
    "send_password_reset_email": ("email", "token"),
}


class EventHooks:
    def __init__(self) -> None:
        self._hooks: dict[str, list[EventHook]] = {}

    # Direct form: on(event, callback) -> None
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
    def on(self, event: Literal["after_oauth_login"], callback: AfterOAuthLoginHook) -> None: ...
    @overload
    def on(
        self, event: Literal["after_oauth_register"], callback: AfterOAuthRegisterHook
    ) -> None: ...
    @overload
    def on(self, event: Literal["send_verification_email"], callback: EmailHook) -> None: ...
    @overload
    def on(self, event: Literal["send_password_reset_email"], callback: EmailHook) -> None: ...
    @overload
    def on(self, event: str, callback: EventHook) -> None: ...
    # Decorator form: @on(event) over the callback definition
    @overload
    def on(self, event: str, callback: None = None) -> Callable[[F], F]: ...

    def on(self, event: str, callback: EventHook | None = None) -> Callable[[F], F] | None:
        """Register a hook for ``event``.

        Two equivalent forms::

            fullauth.hooks.on("after_register", on_register)

            @fullauth.hooks.on("after_register")
            async def on_register(user): ...

        Registering an unknown event name, or a callback whose signature can't
        accept the event's arguments, emits a warning so the mistake surfaces
        here instead of silently never firing.
        """
        if callback is None:

            def decorator(func: F) -> F:
                self._add(event, func)
                return func

            return decorator

        self._add(event, callback)
        return None

    def _add(self, event: str, callback: EventHook) -> None:
        self._validate(event, callback)
        self._hooks.setdefault(event, []).append(callback)

    def _validate(self, event: str, callback: EventHook) -> None:
        if event not in EVENT_PARAMS:
            suggestion = difflib.get_close_matches(event, EVENT_PARAMS, n=1)
            hint = f" Did you mean {suggestion[0]!r}?" if suggestion else ""
            warnings.warn(
                f"Registering a hook for unknown event {event!r}.{hint} "
                f"Known events: {', '.join(EVENT_PARAMS)}. Ignore this if you "
                "emit this custom event yourself via fullauth.hooks.emit().",
                UserWarning,
                stacklevel=4,
            )
            return

        expected = EVENT_PARAMS[event]
        try:
            sig = inspect.signature(callback)
        except (TypeError, ValueError):
            return  # builtins / C callables expose no signature; skip the check
        try:
            sig.bind(**dict.fromkeys(expected))
        except TypeError:
            warnings.warn(
                f"Hook for {event!r} does not accept its arguments "
                f"({', '.join(expected)}); it will fail when the event fires. "
                f"Expected: async def(*, {', '.join(expected)}).",
                UserWarning,
                stacklevel=4,
            )

    def has_listeners(self, event: str) -> bool:
        """Whether at least one hook is registered for ``event``."""
        return bool(self._hooks.get(event))

    async def emit(self, event: str, **kwargs: Any) -> None:
        # Hooks fire after the side effect has committed; a raising hook is logged, not propagated.
        for hook in self._hooks.get(event, []):
            try:
                await hook(**kwargs)
            except Exception:
                logger.exception("hook for event %r raised", event)
