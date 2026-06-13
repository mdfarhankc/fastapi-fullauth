from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        custom_headers: dict[str, str] | None = None,
        hsts: bool = True,
        hsts_value: str = DEFAULT_HSTS_VALUE,
    ) -> None:
        super().__init__(app)
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

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for key, value in self.headers.items():
            response.headers[key] = value
        if self.hsts and self._is_https(request):
            response.headers["Strict-Transport-Security"] = self.hsts_value
        return response
