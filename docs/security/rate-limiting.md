# Rate Limiting

fastapi-fullauth provides two levels of rate limiting:

1. **Auth rate limits** = per-route limits on login, register, password reset, passkey-authenticate, and refresh. Baked into the routers, enabled by default via `AUTH_RATE_LIMIT_ENABLED=True`.
2. **`RateLimitMiddleware`** = a generic per-IP request limiter. **Not wired automatically** = add it yourself with `app.add_middleware(...)`.

Both layers share the same backend (`RATE_LIMIT_BACKEND`: `memory` or `redis`).

## Auth rate limits

Enabled by default. Protects auth endpoints from brute force:

| Route | Default limit | Config |
|-------|--------------|--------|
| Login | 5 per minute | `AUTH_RATE_LIMIT_LOGIN` |
| Register | 3 per minute | `AUTH_RATE_LIMIT_REGISTER` |
| Password reset / email verify | 3 per minute | `AUTH_RATE_LIMIT_PASSWORD_RESET` |
| Passkey authenticate | 10 per minute | `AUTH_RATE_LIMIT_PASSKEY_AUTH` |
| Refresh | 30 per minute | `AUTH_RATE_LIMIT_REFRESH` |

```python
from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        AUTH_RATE_LIMIT_LOGIN=10,           # 10 login attempts per window
        AUTH_RATE_LIMIT_REGISTER=5,         # 5 registrations per window
        AUTH_RATE_LIMIT_WINDOW_SECONDS=120, # 2-minute window
    ),
)
```

Disable entirely:

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    AUTH_RATE_LIMIT_ENABLED=False,
)
```

## Global rate limit middleware

`RateLimitMiddleware` limits every request to the app per client IP. Useful when you don't already have a CDN/WAF in front of the service.

```python
from fastapi_fullauth.middleware import RateLimitMiddleware

app.add_middleware(
    RateLimitMiddleware,
    max_requests=60,
    window_seconds=60,
    trusted_proxy_headers=fullauth.config.TRUSTED_PROXY_HEADERS,
    exempt_paths=["/health", "/metrics"],
)
```

Default: 60 requests per 60 seconds per IP.

Every response includes:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 45
```

When the limit is exceeded, a `429 Too Many Requests` response is returned.

### Redis-backed global limit

Build the limiter with `create_rate_limiter()` so it uses the same backend as the rest of the library:

```python
from fastapi_fullauth.middleware import RateLimitMiddleware
from fastapi_fullauth.protection import create_rate_limiter

limiter = create_rate_limiter(fullauth.config, max_requests=60, window_seconds=60)
app.add_middleware(
    RateLimitMiddleware,
    limiter=limiter,
    trusted_proxy_headers=fullauth.config.TRUSTED_PROXY_HEADERS,
)
```

Set `RATE_LIMIT_BACKEND="redis"` and `REDIS_URL=...` on the config to switch to Redis. The in-memory backend is per-process = fine for a single worker, broken on multi-worker / multi-pod.

## Proxy support

Behind a reverse proxy (Nginx, Cloudflare, AWS ALB), `request.client.host` is the proxy's IP, not the real user's. Configure trusted proxy headers so rate limiting works correctly:

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    TRUSTED_PROXY_HEADERS=["X-Forwarded-For"],
)
```

!!! warning
    Only list headers you trust. If your server is directly exposed to the internet (no proxy), leave this empty = otherwise users can spoof their IP via the header.

When `X-Forwarded-For` contains a chain (e.g. `1.2.3.4, 10.0.0.1`), the first IP (original client) is used.

This setting applies to both auth rate limits and any `RateLimitMiddleware` you wire up.

## Custom backends

Register your own lockout or rate limiter backend:

```python
from fastapi_fullauth.protection.lockout import LockoutManager, register_lockout_backend
from fastapi_fullauth.protection.ratelimit import register_rate_limiter_backend

class DatabaseLockoutManager(LockoutManager):
    def __init__(self, max_attempts, lockout_seconds, **kwargs):
        super().__init__(max_attempts, lockout_seconds)
        # your database setup

    async def is_locked(self, key: str) -> bool: ...
    async def record_failure(self, key: str) -> None: ...
    async def clear(self, key: str) -> None: ...

register_lockout_backend("database", DatabaseLockoutManager)
# Then set LOCKOUT_BACKEND="database" in config
```

The same pattern works for rate limiters with `register_rate_limiter_backend()`.
