# Rate Limiting

fastapi-fullauth provides two levels of rate limiting:

1. **Auth rate limits** — per-route limits on login, register, and password reset (enabled by default)
2. **Global rate limit middleware** — limits all requests per IP (disabled by default)

Both support in-memory and Redis backends.

## Auth rate limits

Enabled by default. Protects auth endpoints from brute force:

| Route | Default limit | Config |
|-------|--------------|--------|
| Login | 5 per minute | `AUTH_RATE_LIMIT_LOGIN` |
| Register | 3 per minute | `AUTH_RATE_LIMIT_REGISTER` |
| Password reset | 3 per minute | `AUTH_RATE_LIMIT_PASSWORD_RESET` |

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
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        AUTH_RATE_LIMIT_ENABLED=False,
    ),
)
```

## Global rate limit middleware

Limits all requests per client IP. Disabled by default:

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        RATE_LIMIT_ENABLED=True,
    ),
)
fullauth.init_app(app)  # middleware is auto-added
```

Default: 60 requests per 60 seconds per IP.

Response headers are included on every response:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 45
```

When the limit is exceeded, a `429 Too Many Requests` response is returned.

## Proxy support

Behind a reverse proxy (Nginx, Cloudflare, AWS ALB), `request.client.host` is the proxy's IP, not the real user's. Configure trusted proxy headers so rate limiting works correctly:

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        TRUSTED_PROXY_HEADERS=["X-Forwarded-For"],
    ),
)
```

!!! warning
    Only list headers you trust. If your server is directly exposed to the internet (no proxy), leave this empty — otherwise users can spoof their IP via the header.

When `X-Forwarded-For` contains a chain (e.g. `1.2.3.4, 10.0.0.1`), the first IP (original client) is used.

This setting applies to both auth rate limits and the global rate limit middleware.

## Redis backend

For multi-process or multi-server deployments, use the Redis backend:

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_BACKEND="redis",
        REDIS_URL="redis://localhost:6379/0",
    ),
)
```

The in-memory backend is per-process. Redis shares state across all workers/servers.

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

## Manual middleware setup

If you need more control, disable auto-middleware and add it yourself:

```python
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware, RateLimiter

fullauth.init_app(app, auto_middleware=False)

app.add_middleware(
    RateLimitMiddleware,
    max_requests=100,
    window_seconds=60,
    exempt_paths=["/health", "/metrics"],
    trusted_proxy_headers=["X-Forwarded-For"],
)
```
