"""Process-wide Redis client sharing.

Several backends can point at the same Redis server (token blacklist, lockout,
rate limiters, challenge store); giving each its own client would open one
connection pool per backend. Instead, backends acquire a shared per-URL client
here and release it in ``aclose()``; the client closes when the last holder
releases it. redis-py connects lazily, so acquiring never touches the network.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis

_clients: dict[str, "Redis"] = {}
_refcounts: dict[str, int] = {}


def acquire_redis(redis_url: str, *, feature: str) -> "Redis":
    """Return the shared client for ``redis_url``, creating it on first use.

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

    client = _clients.get(redis_url)
    if client is None:
        client = aioredis.from_url(redis_url, decode_responses=True)
        _clients[redis_url] = client
    _refcounts[redis_url] = _refcounts.get(redis_url, 0) + 1
    return client


async def release_redis(redis_url: str) -> None:
    """Release one hold on the shared client; close it when none remain."""
    count = _refcounts.get(redis_url, 0)
    if count > 1:
        _refcounts[redis_url] = count - 1
        return
    _refcounts.pop(redis_url, None)
    client = _clients.pop(redis_url, None)
    if client is not None:
        await client.aclose()
