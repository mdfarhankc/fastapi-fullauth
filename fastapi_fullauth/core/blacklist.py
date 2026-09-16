"""Token-blacklist backends. Memory + Redis live side-by-side so the file-pair
pattern matches ``protection/lockout.py`` and ``protection/ratelimit.py``.
"""

import logging
import time

logger = logging.getLogger("fastapi_fullauth.blacklist")

# How often the in-memory stores scan for expired entries. Scanning on every
# write would be O(n) per request; once a minute keeps memory bounded cheaply.
SWEEP_INTERVAL_SECONDS = 60.0


class TokenBlacklist:
    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        raise NotImplementedError

    async def is_blacklisted(self, jti: str) -> bool:
        raise NotImplementedError

    async def is_any_blacklisted(self, *keys: str) -> bool:
        """Whether any of ``keys`` is blacklisted.

        Token checks look up the token id and its session family together.
        Backends that can answer in one round trip should override this.
        """
        for key in keys:
            if await self.is_blacklisted(key):
                return True
        return False

    async def aclose(self) -> None:
        """Release any held resources. No-op unless overridden."""


class InMemoryTokenBlacklist(TokenBlacklist):
    def __init__(self) -> None:
        self._blacklisted: dict[str, float | None] = {}
        self._next_sweep = 0.0

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        now = time.monotonic()
        self._sweep_expired(now)
        # `is None` (not falsy): a ttl of 0 means "already expired", which we
        # floor to an immediate 1s entry rather than the no-expiry sentinel.
        if ttl_seconds is None:
            expires_at: float | None = None
        else:
            expires_at = now + max(1, ttl_seconds)
        self._blacklisted[jti] = expires_at

    def _sweep_expired(self, now: float) -> None:
        # Lookups only evict the key they check, so entries nobody asks about
        # again would otherwise live for the whole process.
        if now < self._next_sweep:
            return
        self._next_sweep = now + SWEEP_INTERVAL_SECONDS
        expired = [
            key
            for key, expires_at in self._blacklisted.items()
            if expires_at is not None and expires_at <= now
        ]
        for key in expired:
            del self._blacklisted[key]

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
        return await self.is_any_blacklisted(jti)

    async def is_any_blacklisted(self, *keys: str) -> bool:
        if not keys:
            return False
        try:
            return bool(await self._redis.exists(*(f"{self._prefix}{key}" for key in keys)) > 0)
        except Exception:
            # Fail closed: if we can't confirm a token is NOT revoked, treat it as
            # revoked so a leaked/blacklisted token can't slip through during a
            # Redis outage. The caller surfaces this as an auth failure, not a 500.
            logger.error(
                "Blacklist Redis error; treating token as revoked (fail-closed): keys=%s",
                keys,
                exc_info=True,
            )
            return True

    async def aclose(self) -> None:
        from fastapi_fullauth.core._redis import release_redis

        if self._redis_url is not None:
            await release_redis(self._redis_url)
            self._redis_url = None
