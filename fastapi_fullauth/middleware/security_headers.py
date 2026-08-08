from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# X-XSS-Protection is intentionally "0": the legacy auditor it enables is
# deprecated and "1; mode=block" can introduce cross-site leak oracles. Modern
# guidance is to disable it and rely on a Content-Security-Policy instead.
DEFAULT_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

DEFAULT_HSTS_VALUE = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware:
    """Standard security response headers (pure ASGI middleware)."""

    def __init__(
        self,
        app: ASGIApp,
        custom_headers: dict[str, str] | None = None,
        hsts: bool = True,
        hsts_value: str = DEFAULT_HSTS_VALUE,
    ) -> None:
        self.app = app
        self.headers = {**DEFAULT_SECURITY_HEADERS}
        if custom_headers:
            self.headers.update(custom_headers)
        self.hsts = hsts
        self.hsts_value = hsts_value

    def _is_https(self, request: Request) -> bool:
        # Honour the proxy's forwarded scheme so HSTS still applies behind a
        # TLS-terminating load balancer, but never emit it on plaintext HTTP
        # (browsers ignore it there and it can pin sibling HTTP-only subdomains).
        if request.url.scheme == "https":
            return True
        return request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        add_hsts = self.hsts and self._is_https(Request(scope))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in self.headers.items():
                    headers[key] = value
                if add_hsts:
                    headers["Strict-Transport-Security"] = self.hsts_value
            await send(message)

        await self.app(scope, receive, send_with_headers)
