"""Token-blacklist backends. Memory + Redis live side-by-side so the file-pair
pattern matches ``protection/lockout.py`` and ``protection/ratelimit.py``.
"""

import time


class TokenBlacklist:
    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        raise NotImplementedError

    async def is_blacklisted(self, jti: str) -> bool:
        raise NotImplementedError


class InMemoryTokenBlacklist(TokenBlacklist):
    def __init__(self) -> None:
        self._blacklisted: dict[str, float | None] = {}

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        expires_at = (time.monotonic() + ttl_seconds) if ttl_seconds else None
        self._blacklisted[jti] = expires_at

    async def is_blacklisted(self, jti: str) -> bool:
        if jti not in self._blacklisted:
            return False
        expires_at = self._blacklisted[jti]
        if expires_at is not None and time.monotonic() > expires_at:
            del self._blacklisted[jti]
            return False
        return True


class RedisTokenBlacklist(TokenBlacklist):
    def __init__(self, redis_url: str, default_ttl_seconds: int = 1800) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for the Redis blacklist backend. "
                "Install it with: pip install fastapi-fullauth[redis]"
            ) from None

        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._default_ttl = default_ttl_seconds
        self._prefix = "fullauth:blacklist:"

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        await self._redis.setex(
            f"{self._prefix}{jti}",
            ttl_seconds or self._default_ttl,
            "1",
        )

    async def is_blacklisted(self, jti: str) -> bool:
        return bool(await self._redis.exists(f"{self._prefix}{jti}") > 0)
