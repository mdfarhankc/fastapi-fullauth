"""Process-wide Redis client sharing.

Several backends can point at the same Redis server (token blacklist, lockout,
rate limiters, challenge store); giving each its own client would open one
connection pool per backend. Instead, backends acquire a shared client here and
release it in ``aclose()``; the client closes when the last holder releases it.
redis-py connects lazily, so acquiring never touches the network.

Clients are shared per (url, event loop). A redis-py asyncio client binds its
connections to the loop that first used them, so handing one client to a second
loop fails at runtime. The key holds the loop *object*, never ``id(loop)``: ids
of closed loops are recycled almost immediately, so an id-keyed entry would
answer for an unrelated new loop with a client bound to the dead one.
"""

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis

# The loop is part of the key, which also keeps it alive for as long as an entry
# refers to it. Acquiring outside a running loop (the usual case, since FullAuth
# is built at import time) uses None and shares one client per url.
RedisClientKey = tuple[str, "asyncio.AbstractEventLoop | None"]


@dataclass
class _Holder:
    client: "Redis"
    count: int


_clients: dict[RedisClientKey, _Holder] = {}


def _current_loop() -> "asyncio.AbstractEventLoop | None":
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def acquire_redis(redis_url: str, *, feature: str) -> tuple["Redis", RedisClientKey]:
    """Return the shared client for ``redis_url`` plus the key to release it with.

    Release with exactly the returned key: re-deriving it at close time would
    pick the wrong entry when the releasing loop is not the acquiring one, and
    could close a client another holder is still using.

    ``feature`` names the caller for the ImportError message when the optional
    redis dependency is missing.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        raise ImportError(
            f"redis package is required for {feature}. "
            "Install it with: pip install fastapi-fullauth[redis]"
        ) from None

    loop = _current_loop()
    key: RedisClientKey = (redis_url, loop)
    holder = _clients.get(key)

    if holder is not None and loop is not None and loop.is_closed():
        # Same loop object, but it has been closed since: its connections are
        # unusable. Start again rather than hand back a dead client.
        _clients.pop(key, None)
        holder = None

    if holder is None:
        holder = _Holder(client=aioredis.from_url(redis_url, decode_responses=True), count=0)
        _clients[key] = holder

    holder.count += 1
    return holder.client, key


async def release_redis(key: RedisClientKey) -> None:
    """Release one hold on a shared client; close it when none remain."""
    holder = _clients.get(key)
    if holder is None:
        return
    holder.count -= 1
    if holder.count > 0:
        return
    _clients.pop(key, None)
    await holder.client.aclose()
