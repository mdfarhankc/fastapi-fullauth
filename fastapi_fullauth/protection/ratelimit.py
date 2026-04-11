import logging
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

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

        # cleanup + count in one pipeline
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zcard(redis_key)
        results = await pipe.execute()

        count = results[1]
        if count >= self.max_requests:
            return False

        # only add if allowed
        pipe = self._redis.pipeline()
        pipe.zadd(redis_key, {f"{now}": now})
        pipe.expire(redis_key, self.window_seconds)
        await pipe.execute()
        return True

    async def remaining(self, key: str) -> int:
        redis_key = f"{self._prefix}{key}"
        now = time.time()
        cutoff = now - self.window_seconds

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zcard(redis_key)
        results = await pipe.execute()

        count = results[1]
        return max(0, self.max_requests - count)

    async def reset_time(self, key: str) -> float:
        redis_key = f"{self._prefix}{key}"
        now = time.time()

        oldest = await self._redis.zrange(redis_key, 0, 0, withscores=True)
        if not oldest:
            return 0.0
        return max(0.0, self.window_seconds - (now - oldest[0][1]))

    async def reset(self, key: str) -> None:
        await self._redis.delete(f"{self._prefix}{key}")


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,  # noqa: ANN001
        limiter: RateLimiter | RedisRateLimiter | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
        exempt_paths: list[str] | None = None,
        trusted_proxy_headers: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.limiter = limiter or RateLimiter(
            max_requests=max_requests, window_seconds=window_seconds
        )
        self.exempt_paths: list[str] = exempt_paths or []
        self.trusted_proxy_headers: list[str] = trusted_proxy_headers or []

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        from fastapi_fullauth.utils import get_client_ip

        client_ip = get_client_ip(request, self.trusted_proxy_headers)

        if not await self.limiter.is_allowed(client_ip):
            reset_in = await self.limiter.reset_time(client_ip)
            logger.info("Rate limit exceeded: ip=%s, path=%s", client_ip, request.url.path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={
                    "X-RateLimit-Limit": str(self.limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(reset_in)),
                },
            )

        response = await call_next(request)

        remaining = await self.limiter.remaining(client_ip)
        reset_in = await self.limiter.reset_time(client_ip)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_in))

        return response
