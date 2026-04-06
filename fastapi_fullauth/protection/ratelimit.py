import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)

    def _cleanup(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        timestamps = self._hits[key]
        timestamps[:] = [t for t in timestamps if t > cutoff]
        if not timestamps:
            del self._hits[key]
        return timestamps

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        self._cleanup(key, now)
        timestamps = self._hits[key]

        if len(timestamps) >= self.max_requests:
            return False

        timestamps.append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        self._cleanup(key, now)
        return max(0, self.max_requests - len(self._hits[key]))

    def reset_time(self, key: str) -> float:
        now = time.monotonic()
        self._cleanup(key, now)
        timestamps = self._hits[key]
        if not timestamps:
            return 0.0
        oldest = timestamps[0]
        return max(0.0, self.window_seconds - (now - oldest))

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,  # noqa: ANN001
        max_requests: int = 60,
        window_seconds: int = 60,
        exempt_paths: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
        self.exempt_paths: list[str] = exempt_paths or []

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        if not self.limiter.is_allowed(client_ip):
            reset_in = self.limiter.reset_time(client_ip)
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

        remaining = self.limiter.remaining(client_ip)
        reset_in = self.limiter.reset_time(client_ip)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_in))

        return response
