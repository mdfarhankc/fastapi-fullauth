import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from fastapi_fullauth.protection.ratelimit import RateLimiter, RedisRateLimiter

logger = logging.getLogger("fastapi_fullauth.ratelimit")


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
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


__all__ = ["RateLimitMiddleware"]
