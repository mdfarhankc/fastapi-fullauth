import hashlib
import hmac
import logging
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

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
    """

    def __init__(
        self,
        app,
        secret: str | None = None,
        cookie_name: str = "fullauth_csrf",
        exempt_paths: list[str] | None = None,
        cookie_secure: bool = True,
        cookie_samesite: str = "lax",
        cookie_httponly: bool = False,
        cookie_domain: str | None = None,
        header_name: str = "X-CSRF-Token",
    ):
        super().__init__(app)

        if secret is None:
            secret = self._resolve_secret()

        self.secret = secret
        self.cookie_name = cookie_name
        self.exempt_paths: list[str] = exempt_paths or []
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_httponly = cookie_httponly
        self.cookie_domain = cookie_domain
        self.header_name = header_name

    @staticmethod
    def _resolve_secret() -> str:
        from fastapi_fullauth.config import FullAuthConfig

        cfg = FullAuthConfig()  # type: ignore[call-arg]
        return cfg.CSRF_SECRET or cfg.SECRET_KEY

    def _is_exempt(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.exempt_paths)

    async def dispatch(self, request: Request, call_next) -> Response:
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
