"""Token-blacklist backends. Memory + Redis live side-by-side so the file-pair
pattern matches ``protection/lockout.py`` and ``protection/ratelimit.py``.
"""

import logging
import time

logger = logging.getLogger("fastapi_fullauth.blacklist")


class TokenBlacklist:
    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        raise NotImplementedError

    async def is_blacklisted(self, jti: str) -> bool:
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any held resources. No-op unless overridden."""


class InMemoryTokenBlacklist(TokenBlacklist):
    def __init__(self) -> None:
        self._blacklisted: dict[str, float | None] = {}

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        # `is None` (not falsy): a ttl of 0 means "already expired", which we
        # floor to an immediate 1s entry rather than the no-expiry sentinel.
        if ttl_seconds is None:
            expires_at: float | None = None
        else:
            expires_at = time.monotonic() + max(1, ttl_seconds)
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
        from fastapi_fullauth.core._redis import acquire_redis

        self._redis = acquire_redis(redis_url, feature="the Redis blacklist backend")
        self._redis_url: str | None = redis_url
        self._default_ttl = default_ttl_seconds
        self._prefix = "fullauth:blacklist:"

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        # Check `is None`, not falsy: a ttl of 0 means "already expired" and must
        # floor to a 1s entry, never silently fall back to the default. setex
        # also rejects a 0 ttl outright.
        ttl = self._default_ttl if ttl_seconds is None else max(1, ttl_seconds)
        await self._redis.setex(f"{self._prefix}{jti}", ttl, "1")

    async def is_blacklisted(self, jti: str) -> bool:
        try:
            return bool(await self._redis.exists(f"{self._prefix}{jti}") > 0)
        except Exception:
            # Fail closed: if we can't confirm a token is NOT revoked, treat it as
            # revoked so a leaked/blacklisted token can't slip through during a
            # Redis outage. The caller surfaces this as an auth failure, not a 500.
            logger.error(
                "Blacklist Redis error; treating token as revoked (fail-closed): jti=%s",
                jti,
                exc_info=True,
            )
            return True

    async def aclose(self) -> None:
        from fastapi_fullauth.core._redis import release_redis

        if self._redis_url is not None:
            await release_redis(self._redis_url)
            self._redis_url = None
