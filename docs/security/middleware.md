# Middleware

fastapi-fullauth ships three middleware classes. None of them are wired automatically — `init_app()` only mounts routers. Import what you want and call `app.add_middleware(...)` yourself:

```python
from fastapi_fullauth.middleware import (
    SecurityHeadersMiddleware,
    CSRFMiddleware,
    RateLimitMiddleware,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware, secret=fullauth.config.CSRF_SECRET or fullauth.config.SECRET_KEY)
fullauth.init_app(app)
```

> FastAPI applies middleware in reverse order, so `add_middleware` calls before `init_app` execute outermost. Add the broadest protections (security headers, rate limiting) first.

## Security Headers

Adds standard security headers to every response:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` |

### Custom headers

Override or add headers:

```python
from fastapi_fullauth.middleware import SecurityHeadersMiddleware

app.add_middleware(
    SecurityHeadersMiddleware,
    custom_headers={
        "X-Frame-Options": "SAMEORIGIN",  # override default
        "X-Custom-Header": "value",       # add new
    },
)
```

## CSRF Protection

Use for cookie-based auth where the frontend and backend share a domain. `secret` must be at least 32 characters — pass `config.CSRF_SECRET` (or fall back to `SECRET_KEY`):

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.middleware import CSRFMiddleware

config = FullAuthConfig(
    SECRET_KEY="…",
    CSRF_SECRET="optional-separate-secret",  # falls back to SECRET_KEY
)
fullauth = FullAuth(adapter=adapter, config=config)

app.add_middleware(
    CSRFMiddleware,
    secret=config.CSRF_SECRET or config.SECRET_KEY,
    cookie_secure=config.COOKIE_SECURE,
    cookie_samesite=config.COOKIE_SAMESITE,
    cookie_domain=config.COOKIE_DOMAIN,
)
```

### How it works

Uses the **double-submit cookie** pattern:

1. On `GET` requests, a signed CSRF cookie (`fullauth_csrf`) is set
2. On state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`), the client must send the cookie value in the `X-CSRF-Token` header
3. The middleware verifies the cookie signature and compares cookie vs header

### Frontend integration

```javascript
// read the CSRF cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('fullauth_csrf='))
  ?.split('=')[1];

// include it in requests
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

```python
app.add_middleware(
    CSRFMiddleware,
    secret="your-32-plus-character-secret-here…",
    exempt_paths=["/api/v1/webhooks"],
)
```

## Rate Limiting

See [Rate Limiting](rate-limiting.md) for full details.
