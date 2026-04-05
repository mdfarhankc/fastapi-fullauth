from collections.abc import Awaitable, Callable
from typing import Any

EventHook = Callable[..., Awaitable[Any]]


class EventHooks:
    def __init__(self) -> None:
        self._hooks: dict[str, list[EventHook]] = {}

    def on(self, event: str, callback: EventHook) -> None:
        self._hooks.setdefault(event, []).append(callback)

    async def emit(self, event: str, **kwargs: Any) -> None:
        for hook in self._hooks.get(event, []):
            await hook(**kwargs)
