import hashlib
import hmac
import logging
import secrets
from typing import Literal
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger("fastapi_fullauth.csrf")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _sign_token(token: str, secret: str) -> str:
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def _make_csrf_value(secret: str) -> str:
    token = secrets.token_hex(32)
    sig = _sign_token(token, secret)
    return f"{token}.{sig}"


def _verify_csrf_value(value: str, secret: str) -> bool:
    parts = value.split(".", 1)
    if len(parts) != 2:
        return False
    token, sig = parts
    expected = _sign_token(token, secret)
    return hmac.compare_digest(sig, expected)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection.

    Sets a signed CSRF cookie on safe requests. State-changing requests
    must include an X-CSRF-Token header matching the cookie value.

    The signed double-submit token proves the value was server-issued but is not
    bound to the user's session, so a party able to *write* a cookie for the
    domain (sibling-subdomain takeover, MITM on a plaintext sibling) could plant
    a matching cookie+header pair. Set ``trusted_origins`` to the front-end
    origins you serve to also require a matching Origin/Referer on state-changing
    requests - the recommended defence in depth for cookie-based auth.
    """

    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        cookie_name: str = "fullauth_csrf",
        exempt_paths: list[str] | None = None,
        cookie_secure: bool = True,
        cookie_samesite: Literal["lax", "strict", "none"] = "lax",
        cookie_httponly: bool = False,
        cookie_domain: str | None = None,
        header_name: str = "X-CSRF-Token",
        trusted_origins: list[str] | None = None,
    ) -> None:
        super().__init__(app)

        if not secret or len(secret) < 32:
            raise ValueError(
                "CSRFMiddleware requires a `secret` of at least 32 characters. "
                "Pass your FullAuthConfig SECRET_KEY (or a dedicated key)."
            )

        if cookie_samesite == "none" and not cookie_secure:
            raise ValueError(
                "CSRFMiddleware with cookie_samesite='none' requires cookie_secure=True; "
                "browsers reject a SameSite=None cookie that is not also Secure."
            )

        self.secret = secret
        self.cookie_name = cookie_name
        self.exempt_paths: list[str] = exempt_paths or []
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_httponly = cookie_httponly
        self.cookie_domain = cookie_domain
        self.header_name = header_name
        # Normalise to scheme://host[:port] with any trailing slash removed.
        self.trusted_origins: set[str] = {o.rstrip("/") for o in (trusted_origins or [])}

    def _is_exempt(self, path: str) -> bool:
        # Anchor on path-segment boundaries so exempting "/api/foo" does not also
        # exempt "/api/foobar"; only "/api/foo" itself and "/api/foo/..." match.
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.exempt_paths)

    def _origin_allowed(self, request: Request) -> bool:
        """When trusted_origins is configured, a present Origin/Referer must match
        one of them. Requests with neither header (non-browser clients) defer to
        the token check; browsers always send Origin on cross-site unsafe requests."""
        if not self.trusted_origins:
            return True
        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer")
            if referer:
                parsed = urlparse(referer)
                if parsed.scheme and parsed.netloc:
                    origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin is None:
            return True
        return origin.rstrip("/") in self.trusted_origins

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method.upper()
        path = request.url.path

        if self._is_exempt(path):
            return await call_next(request)

        if method in SAFE_METHODS:
            response = await call_next(request)
            if self.cookie_name not in request.cookies:
                csrf_value = _make_csrf_value(self.secret)
                response.set_cookie(
                    key=self.cookie_name,
                    value=csrf_value,
                    httponly=self.cookie_httponly,
                    secure=self.cookie_secure,
                    samesite=self.cookie_samesite,
                    domain=self.cookie_domain,
                    path="/",
                )
            return response

        if not self._origin_allowed(request):
            logger.warning("CSRF origin not allowed: %s %s", method, path)
            return JSONResponse(
                {"detail": "CSRF origin check failed."},
                status_code=403,
            )

        cookie_value = request.cookies.get(self.cookie_name)
        header_value = request.headers.get(self.header_name)

        if not cookie_value or not header_value:
            logger.warning("CSRF token missing: %s %s", method, path)
            return JSONResponse(
                {"detail": "CSRF token missing."},
                status_code=403,
            )

        if not _verify_csrf_value(cookie_value, self.secret):
            logger.warning("CSRF cookie signature invalid: %s %s", method, path)
            return JSONResponse(
                {"detail": "CSRF cookie signature invalid."},
                status_code=403,
            )

        if not hmac.compare_digest(cookie_value, header_value):
            logger.warning("CSRF token mismatch: %s %s", method, path)
            return JSONResponse(
                {"detail": "CSRF token mismatch."},
                status_code=403,
            )

        return await call_next(request)
