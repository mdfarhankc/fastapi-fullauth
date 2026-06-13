# Middleware

fastapi-fullauth ships three middleware classes. None of them are wired automatically; `init_app()` only mounts routers. Import what you want and call `app.add_middleware(...)` yourself.

## Middleware order

FastAPI applies middleware in reverse registration order. Register the broadest protections first (they execute outermost), then narrow ones, then init_app:

```python
from fastapi_fullauth.middleware import (
    SecurityHeadersMiddleware,
    CSRFMiddleware,
    RateLimitMiddleware,
)

# 1. Security headers (outermost, runs on every response)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate limiting (before auth routes)
app.add_middleware(RateLimitMiddleware, max_requests=60, window_seconds=60)

# 3. CSRF protection (before auth routes, if using cookie auth)
app.add_middleware(CSRFMiddleware, secret=config.SECRET_KEY)

# 4. Auth routers (innermost)
fullauth.init_app(app)
```

## When to use which middleware

| Middleware | Use when |
|-----------|----------|
| `SecurityHeadersMiddleware` | Always. No reason not to. |
| `CSRFMiddleware` | Using cookie-based auth (`CookieBackend`). Not needed for bearer-only SPAs. |
| `RateLimitMiddleware` | No CDN/WAF in front of your service, or you want app-level rate limiting. |

!!! note
    CSRF protection is only needed for cookie-based auth. Cookies are sent automatically by the browser on every request, which is what makes CSRF attacks possible. Bearer tokens in the `Authorization` header must be explicitly attached by JavaScript, so they're not vulnerable to CSRF.

## Security Headers

Adds standard security headers to every response:

| Header | Default value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-XSS-Protection` | `0` | Disables the deprecated legacy XSS auditor (rely on a CSP) |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Forces HTTPS for 1 year — **sent only over HTTPS** |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Disables browser APIs |

!!! note "HSTS is HTTPS-only"
    `Strict-Transport-Security` is emitted only when the request is HTTPS — directly, or via an `X-Forwarded-Proto: https` header from a trusted proxy. This prevents a stray plaintext-HTTP deploy from pinning HSTS (with `includeSubDomains`) across sibling subdomains. Disable it entirely with `SecurityHeadersMiddleware(app, hsts=False)`, or change the policy with `hsts_value=...`.

!!! info "`X-XSS-Protection` is `0` on purpose"
    The legacy auditor this header enabled is deprecated, and `1; mode=block` is known to introduce cross-site leak oracles in browsers that still honour it. The modern guidance is to disable it and rely on a `Content-Security-Policy`.

### Custom headers

Override or add headers:

```python
app.add_middleware(
    SecurityHeadersMiddleware,
    custom_headers={
        "X-Frame-Options": "SAMEORIGIN",  # override default
        "Content-Security-Policy": "default-src 'self'",  # add new
    },
)
```

!!! tip
    `Content-Security-Policy` is not included by default because it varies heavily by application. Add it via `custom_headers` with a policy that matches your frontend setup.

## CSRF Protection

Uses the **double-submit cookie** pattern:

1. On safe requests (`GET`, `HEAD`, `OPTIONS`), a signed CSRF cookie (`fullauth_csrf`) is set
2. On state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`), the client must send the cookie value in the `X-CSRF-Token` header
3. The middleware verifies the HMAC-SHA256 signature on the cookie and compares the cookie value against the header

### Setup

```python
app.add_middleware(
    CSRFMiddleware,
    secret=config.SECRET_KEY,
    cookie_secure=True,
    cookie_samesite="lax",
    cookie_domain=None,
)
```

The `secret` must be at least 32 characters. Pass `config.SECRET_KEY`, or your own dedicated key if you want to rotate it independently. Match the cookie attributes to whatever you pass your `CookieBackend`.

### Origin allow-list (recommended)

The signed double-submit token proves the cookie was server-issued but is **not bound to the user's session**, so a party able to *write* a cookie for your domain (a sibling-subdomain takeover, or a MITM on a plaintext sibling host) could plant a matching cookie+header pair. Add `trusted_origins` to also require a matching `Origin`/`Referer` on state-changing requests — the recommended defence in depth for cookie-based auth:

```python
app.add_middleware(
    CSRFMiddleware,
    secret=config.SECRET_KEY,
    trusted_origins=["https://app.example.com"],
)
```

When set, a state-changing request whose `Origin` (or `Referer`) is not in the list is rejected even if it carries a valid token. Requests with no `Origin`/`Referer` (non-browser clients) fall back to the token check, so server-to-server callers are unaffected.

### Frontend integration

Your frontend must read the CSRF cookie and send it as a header:

```javascript
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('fullauth_csrf='))
  ?.split('=')[1];

fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken,
  },
  credentials: 'include',
  body: JSON.stringify({ email, password }),
});
```

### Exempt paths

Skip CSRF for specific paths (e.g. webhooks that receive external POST requests):

```python
app.add_middleware(
    CSRFMiddleware,
    secret="your-32-plus-character-secret-here",
    exempt_paths=["/api/v1/webhooks"],
)
```

Exempt paths are matched on path-segment boundaries: `"/api/v1/webhooks"` exempts that exact path and anything under `"/api/v1/webhooks/"`, but **not** a sibling like `"/api/v1/webhooks-admin"`.

## Rate Limiting

See [Rate Limiting](rate-limiting.md) for the full guide on both auth rate limits and the global middleware.
