import logging
import math

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastapi_fullauth.protection.ratelimit import RateLimiter, RedisRateLimiter

logger = logging.getLogger("fastapi_fullauth.ratelimit")


class RateLimitMiddleware:
    """Global per-IP rate limiting (pure ASGI middleware)."""

    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter | RedisRateLimiter | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
        exempt_paths: list[str] | None = None,
        trusted_proxy_headers: list[str] | None = None,
        trusted_proxy_count: int = 1,
    ) -> None:
        self.app = app
        self.limiter = limiter or RateLimiter(
            max_requests=max_requests, window_seconds=window_seconds
        )
        self.exempt_paths: list[str] = exempt_paths or []
        self.trusted_proxy_headers: list[str] = trusted_proxy_headers or []
        self.trusted_proxy_count: int = trusted_proxy_count

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if request.url.path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        from fastapi_fullauth.utils import get_client_ip

        client_ip = get_client_ip(request, self.trusted_proxy_headers, self.trusted_proxy_count)

        if not await self.limiter.is_allowed(client_ip):
            reset_in = await self.limiter.reset_time(client_ip)
            logger.info("Rate limit exceeded: ip=%s, path=%s", client_ip, request.url.path)
            response = JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={
                    "X-RateLimit-Limit": str(self.limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(math.ceil(reset_in)),
                    "Retry-After": str(math.ceil(reset_in)),
                },
            )
            await response(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                remaining = await self.limiter.remaining(client_ip)
                reset_in = await self.limiter.reset_time(client_ip)
                headers = MutableHeaders(scope=message)
                headers["X-RateLimit-Limit"] = str(self.limiter.max_requests)
                headers["X-RateLimit-Remaining"] = str(remaining)
                headers["X-RateLimit-Reset"] = str(math.ceil(reset_in))
            await send(message)

        await self.app(scope, receive, send_with_headers)


__all__ = ["RateLimitMiddleware"]
