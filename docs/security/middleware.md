# Middleware

fastapi-fullauth includes three middleware components. By default, `init_app()` auto-wires them based on config flags. Pass `auto_middleware=False` to manage them yourself.

```python
fullauth.init_app(app, auto_middleware=False)
```

## Security Headers

Enabled by default (`INJECT_SECURITY_HEADERS=True`). Adds standard security headers to every response:

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

Disabled by default (`CSRF_ENABLED=False`). Enable it for cookie-based auth where the frontend and backend share a domain:

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    csrf_enabled=True,
    csrf_secret="optional-separate-secret",  # falls back to SECRET_KEY
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
from fastapi_fullauth.middleware import CSRFMiddleware

app.add_middleware(
    CSRFMiddleware,
    secret="your-secret",
    exempt_paths=["/api/v1/webhooks"],
)
```

## Rate Limiting

See [Rate Limiting](rate-limiting.md) for full details.
