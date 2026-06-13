import logging
import secrets
import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi_fullauth.config import FullAuthConfig

logger = logging.getLogger("fastapi_fullauth.ratelimit")


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _cleanup(self, key: str, now: float) -> deque[float]:
        cutoff = now - self.window_seconds
        timestamps = self._hits[key]
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if not timestamps:
            del self._hits[key]
        return timestamps

    async def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        self._cleanup(key, now)
        timestamps = self._hits[key]

        if len(timestamps) >= self.max_requests:
            return False

        timestamps.append(now)
        return True

    async def remaining(self, key: str) -> int:
        now = time.monotonic()
        self._cleanup(key, now)
        return max(0, self.max_requests - len(self._hits[key]))

    async def reset_time(self, key: str) -> float:
        now = time.monotonic()
        self._cleanup(key, now)
        timestamps = self._hits[key]
        if not timestamps:
            return 0.0
        oldest = timestamps[0]
        return max(0.0, self.window_seconds - (now - oldest))

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)

    async def aclose(self) -> None:
        """Release any held resources. No-op for the in-memory limiter."""


class RedisRateLimiter:
    """Redis-backed sliding window rate limiter using sorted sets."""

    def __init__(
        self,
        redis_url: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for the Redis rate limiter. "
                "Install it with: pip install fastapi-fullauth[redis]"
            ) from None

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._prefix = "fullauth:ratelimit:"

    async def is_allowed(self, key: str) -> bool:
        redis_key = f"{self._prefix}{key}"
        now = time.time()
        cutoff = now - self.window_seconds

        try:
            # Cleanup, add, and count in ONE atomic MULTI/EXEC. Counting in a
            # separate round-trip from the add (check-then-act) is a TOCTOU race:
            # a concurrent burst all reads count<max before any adds, so they all
            # pass and blow the limit. Here we add first, then read the post-add
            # cardinality atomically, and back our own member out if we exceeded.
            #
            # The member must be unique per hit; the bare timestamp collides for
            # requests in the same clock tick (zadd would overwrite, undercounting),
            # so we append a random suffix.
            member = f"{now}:{secrets.token_hex(8)}"
            pipe = self._redis.pipeline(transaction=True)
            pipe.zremrangebyscore(redis_key, "-inf", cutoff)
            pipe.zadd(redis_key, {member: now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, self.window_seconds)
            results = await pipe.execute()

            count = results[2]
            if count > self.max_requests:
                # We pushed the window over the limit; remove our own member so we
                # don't permanently inflate the count, and reject.
                await self._redis.zrem(redis_key, member)
                return False
            return True
        except Exception:
            # Fail open: a Redis outage must not lock every client out of login.
            # We trade rate-limit enforcement for availability and log loudly so
            # the outage is visible. (The token blacklist, by contrast, fails
            # closed - see RedisTokenBlacklist.is_blacklisted.)
            logger.error("Rate limiter Redis error; allowing request (fail-open)", exc_info=True)
            return True

    async def remaining(self, key: str) -> int:
        redis_key = f"{self._prefix}{key}"
        now = time.time()
        cutoff = now - self.window_seconds

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zcard(redis_key)
        results = await pipe.execute()

        count: int = results[1]
        return max(0, self.max_requests - count)

    async def reset_time(self, key: str) -> float:
        redis_key = f"{self._prefix}{key}"
        now = time.time()

        oldest = await self._redis.zrange(redis_key, 0, 0, withscores=True)
        if not oldest:
            return 0.0
        oldest_score: float = oldest[0][1]
        return max(0.0, self.window_seconds - (now - oldest_score))

    async def reset(self, key: str) -> None:
        await self._redis.delete(f"{self._prefix}{key}")

    async def aclose(self) -> None:
        await self._redis.aclose()


_rate_limiter_registry: dict[str, type[RateLimiter] | type[RedisRateLimiter]] = {
    "memory": RateLimiter,
    "redis": RedisRateLimiter,
}


def register_rate_limiter_backend(name: str, cls: type) -> None:
    """Register a custom rate limiter backend.

    The class must accept ``max_requests`` and ``window_seconds`` kwargs.
    Redis-based backends also receive ``redis_url``.

    Usage::

        class DatabaseRateLimiter:
            def __init__(self, max_requests, window_seconds, **kwargs): ...
            async def is_allowed(self, key: str) -> bool: ...

        register_rate_limiter_backend("database", DatabaseRateLimiter)
        # Then set RATE_LIMIT_BACKEND="database" in config
    """
    _rate_limiter_registry[name] = cls


def create_rate_limiter(
    config: "FullAuthConfig", max_requests: int, window_seconds: int
) -> RateLimiter | RedisRateLimiter:
    """Create a rate limiter backend based on config.

    Args:
        config: FullAuthConfig instance.
        max_requests: Maximum requests per window.
        window_seconds: Window size in seconds.
    """
    backend_cls = _rate_limiter_registry.get(config.RATE_LIMIT_BACKEND)
    if backend_cls is None:
        raise ValueError(
            f"Unknown rate limiter backend: {config.RATE_LIMIT_BACKEND}. "
            f"Available: {', '.join(sorted(_rate_limiter_registry))}. "
            f"Register custom backends with register_rate_limiter_backend()."
        )

    kwargs: dict[str, Any] = {"max_requests": max_requests, "window_seconds": window_seconds}
    if config.RATE_LIMIT_BACKEND == "redis":
        if not config.REDIS_URL:
            raise ValueError("REDIS_URL must be set when RATE_LIMIT_BACKEND='redis'")
        kwargs["redis_url"] = config.REDIS_URL

    return backend_cls(**kwargs)


class AuthRateLimiter:
    """Per-route auth rate limiter. Wraps individual RateLimiter instances
    for login, register, and password-reset routes."""

    def __init__(self, config: "FullAuthConfig") -> None:
        self._limiters: dict[str, RateLimiter | RedisRateLimiter] = {}
        if not config.AUTH_RATE_LIMIT_ENABLED:
            return

        window = config.AUTH_RATE_LIMIT_WINDOW_SECONDS
        limits = config.AUTH_RATE_LIMITS
        self._limiters["login"] = create_rate_limiter(config, limits.login, window)
        self._limiters["register"] = create_rate_limiter(config, limits.register, window)
        self._limiters["password-reset"] = create_rate_limiter(
            config, limits.password_reset, window
        )
        self._limiters["passkey-authenticate"] = create_rate_limiter(
            config, limits.passkey_auth, window
        )
        self._limiters["refresh"] = create_rate_limiter(config, limits.refresh, window)

    async def aclose(self) -> None:
        for limiter in self._limiters.values():
            # Custom backends registered via register_rate_limiter_backend()
            # aren't required to subclass the built-ins, so aclose is optional.
            close = getattr(limiter, "aclose", None)
            if close is not None:
                await close()

    async def check(self, route_name: str, client_ip: str) -> None:
        limiter = self._limiters.get(route_name)
        if limiter and not await limiter.is_allowed(client_ip):
            from fastapi import HTTPException

            reset_in = await limiter.reset_time(client_ip)
            logger.warning("Auth rate limit exceeded: route=%s, ip=%s", route_name, client_ip)
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again later.",
                headers={
                    "X-RateLimit-Limit": str(limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(reset_in)),
                    "Retry-After": str(int(reset_in)),
                },
            )
