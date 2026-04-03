
import hashlib
import hmac
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _sign_token(token: str, secret: str) -> str:
    """Return an HMAC-SHA256 signature for the given token."""
    return hmac.new(
        secret.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def _make_csrf_value(secret: str) -> str:
    """Generate a random token and return ``token.signature``."""
    token = secrets.token_hex(32)
    sig = _sign_token(token, secret)
    return f"{token}.{sig}"


def _verify_csrf_value(value: str, secret: str) -> bool:
    """Verify that a ``token.signature`` pair is authentic."""
    parts = value.split(".", 1)
    if len(parts) != 2:
        return False
    token, sig = parts
    expected = _sign_token(token, secret)
    return hmac.compare_digest(sig, expected)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection.

    On safe requests (GET/HEAD/OPTIONS) a signed CSRF cookie is set when one is
    not already present.  On state-changing requests the middleware requires an
    ``X-CSRF-Token`` header whose value matches the cookie.  Both values are
    HMAC-signed so they cannot be forged without the server secret.

    Parameters
    ----------
    app:
        The ASGI application.
    secret:
        The HMAC signing secret.  Falls back to ``FullAuthConfig.CSRF_SECRET``
        then ``FullAuthConfig.SECRET_KEY`` when *None*.
    cookie_name:
        Name of the CSRF cookie.  Defaults to ``"fullauth_csrf"``.
    exempt_paths:
        A list of path prefixes that skip CSRF validation (e.g.
        ``["/auth/login"]``).
    cookie_secure:
        Whether the cookie requires HTTPS.
    cookie_samesite:
        ``SameSite`` attribute for the cookie.
    cookie_httponly:
        Whether the cookie is ``HttpOnly``.  Defaults to *False* so that
        front-end JavaScript can read the token and send it back in the header.
    cookie_domain:
        Optional domain scope for the cookie.
    header_name:
        Name of the request header carrying the CSRF token.
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_secret() -> str:
        """Pull the secret from FullAuthConfig at import time."""
        from fastapi_fullauth.config import FullAuthConfig

        cfg = FullAuthConfig()  # type: ignore[call-arg]
        return cfg.CSRF_SECRET or cfg.SECRET_KEY

    def _is_exempt(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.exempt_paths)

    # ------------------------------------------------------------------
    # Middleware entry point
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method.upper()
        path = request.url.path

        if self._is_exempt(path):
            return await call_next(request)

        # --- Safe methods: ensure a CSRF cookie is present ---------------
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

        # --- State-changing methods: validate token ----------------------
        cookie_value = request.cookies.get(self.cookie_name)
        header_value = request.headers.get(self.header_name)

        if not cookie_value or not header_value:
            return JSONResponse(
                {"detail": "CSRF token missing."},
                status_code=403,
            )

        if not _verify_csrf_value(cookie_value, self.secret):
            return JSONResponse(
                {"detail": "CSRF cookie signature invalid."},
                status_code=403,
            )

        if not hmac.compare_digest(cookie_value, header_value):
            return JSONResponse(
                {"detail": "CSRF token mismatch."},
                status_code=403,
            )

        return await call_next(request)
