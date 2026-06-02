# Rate Limiting

fastapi-fullauth provides two levels of rate limiting, plus account lockout for brute-force protection:

1. **Auth rate limits**: per-route limits on login, register, password reset, passkey-authenticate, and refresh. Built into the routers, enabled by default.
2. **`RateLimitMiddleware`**: a generic per-IP request limiter. Not wired automatically; add it yourself with `app.add_middleware(...)`.
3. **Account lockout**: locks accounts after too many failed login attempts. Different from rate limiting: lockout is per-account (by email), rate limiting is per-IP.

## Auth rate limits

Enabled by default. Protects auth endpoints from brute force:

| Route | Default limit | Config |
|-------|:---:|---|
| Login | 5/min | `AUTH_RATE_LIMIT_LOGIN` |
| Register | 3/min | `AUTH_RATE_LIMIT_REGISTER` |
| Password reset / email verify | 3/min | `AUTH_RATE_LIMIT_PASSWORD_RESET` |
| Passkey authenticate | 10/min | `AUTH_RATE_LIMIT_PASSKEY_AUTH` |
| Refresh | 30/min | `AUTH_RATE_LIMIT_REFRESH` |

All routes share the same window (`AUTH_RATE_LIMIT_WINDOW_SECONDS`, default 60). The algorithm is sliding-window: it tracks request timestamps and counts how many fall within the current window.

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    AUTH_RATE_LIMIT_LOGIN=10,           # 10 login attempts per window
    AUTH_RATE_LIMIT_REGISTER=5,         # 5 registrations per window
    AUTH_RATE_LIMIT_WINDOW_SECONDS=120, # 2-minute window
)
```

When a limit is exceeded, the route returns `429 Too Many Requests` with a `Retry-After` header.

Disable entirely:

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    AUTH_RATE_LIMIT_ENABLED=False,
)
```

### How auth rate limits differ from lockout

Auth rate limits are **per-IP**: they prevent a single IP from hammering auth endpoints. Account lockout is **per-account**: it locks a specific email after too many failed logins, regardless of which IP the attempts came from.

Both can trigger at the same time. A single attacker hitting one account will see rate limiting first (IP-based, 5 attempts), then lockout kicks in (account-based, 5 failures).

## Account lockout

Locks an account after repeated failed login attempts. Enabled by default.

| Setting | Default | Description |
|---------|---------|-------------|
| `LOCKOUT_ENABLED` | `True` | Enable/disable lockout |
| `LOCKOUT_BACKEND` | `"memory"` | `"memory"` or `"redis"` |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed attempts before lockout |
| `LOCKOUT_DURATION_MINUTES` | `15` | How long the account stays locked |

When an account is locked, login attempts return `423 Locked` with a message indicating the lockout duration.

Lockout is checked at the start of every login attempt, before any password verification. A successful login clears the failure counter.

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    MAX_LOGIN_ATTEMPTS=10,
    LOCKOUT_DURATION_MINUTES=30,
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

Every response includes rate limit headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 45
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Seconds until the window resets |

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

Set `RATE_LIMIT_BACKEND="redis"` and `REDIS_URL=...` on the config to switch to Redis. The in-memory backend is per-process; fine for a single worker, broken on multi-worker / multi-pod.

## Proxy support

Behind a reverse proxy (Nginx, Cloudflare, AWS ALB), `request.client.host` is the proxy's IP, not the real user's. Configure trusted proxy headers so rate limiting and lockout work correctly:

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    TRUSTED_PROXY_HEADERS=["X-Forwarded-For"],
)
```

!!! warning
    Only list headers you trust. If your server is directly exposed to the internet (no proxy), leave this empty; otherwise users can spoof their IP via the header.

When `X-Forwarded-For` contains a chain (e.g. `1.2.3.4, 10.0.0.1`), the first IP (original client) is used.

Common proxy configurations:

| Proxy | Header to trust |
|-------|----------------|
| Nginx (`proxy_set_header X-Forwarded-For`) | `X-Forwarded-For` |
| Cloudflare | `CF-Connecting-IP` |
| AWS ALB | `X-Forwarded-For` |
| Google Cloud Load Balancer | `X-Forwarded-For` |

This setting applies to both auth rate limits and any `RateLimitMiddleware` you wire up.

## Custom backends

Register your own lockout or rate limiter backend:

```python
from fastapi_fullauth.protection.lockout import LockoutManager, register_lockout_backend
from fastapi_fullauth.protection.ratelimit import register_rate_limiter_backend

class DatabaseLockoutManager(LockoutManager):
    def __init__(self, max_attempts, lockout_seconds, **kwargs):
        super().__init__(max_attempts, lockout_seconds)

    async def is_locked(self, key: str) -> bool: ...
    async def record_failure(self, key: str) -> None: ...
    async def clear(self, key: str) -> None: ...

register_lockout_backend("database", DatabaseLockoutManager)
# Then set LOCKOUT_BACKEND="database" in config
```

The same pattern works for rate limiters with `register_rate_limiter_backend()`.

## Production recommendations

- Use **Redis backends** for all protection subsystems (`FULLAUTH_BACKEND=redis`). In-memory backends are per-process and don't work correctly with multiple workers.
- **Layer auth rate limits with global middleware**: auth rate limits protect specific routes (login, register), while `RateLimitMiddleware` protects the entire app from IP-level abuse.
- If you have a **CDN or WAF** (Cloudflare, AWS WAF), DDoS protection happens at that layer. The library's rate limiting handles application-level abuse (credential stuffing, enumeration).
- Configure **TRUSTED_PROXY_HEADERS** correctly. Without it, all requests appear to come from the proxy's IP, and rate limiting is effectively disabled.
