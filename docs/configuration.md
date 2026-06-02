# Configuration

All configuration is managed through `FullAuthConfig`, a [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) class. Every option can be set via environment variables with the `FULLAUTH_` prefix.

## Usage

Pass config inline or as an object:

=== "Config object"

    ```python
    from fastapi_fullauth import FullAuth, FullAuthConfig

    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(
            SECRET_KEY="...",
            ACCESS_TOKEN_EXPIRE_MINUTES=60,
            API_PREFIX="/api/v2",
        ),
    )
    ```

=== "Environment variables"

    ```bash
    export FULLAUTH_SECRET_KEY="your-secret-key"
    export FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=60
    ```

    ```python
    from fastapi_fullauth import FullAuth

    # reads from env automatically
    fullauth = FullAuth(adapter=adapter)
    ```

## Reading from a `.env` file

`FullAuthConfig` reads a `.env` file in the current working directory by default (via pydantic-settings). Drop a `.env` next to your app entry point:

```bash
# .env
FULLAUTH_SECRET_KEY=replace-me-with-32-random-bytes
FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=15
# Setting REDIS_URL switches all subsystems to Redis automatically.
FULLAUTH_REDIS_URL=redis://localhost:6379/0
```

Then `FullAuthConfig()` picks it up; no extra wiring needed.

!!! tip "List settings take a comma-separated string"
    `ORIGINS`, `TRUSTED_PROXY_HEADERS`, `PASSKEY_ORIGINS`, and `ROUTER_TAGS` accept a
    plain comma-separated value from the environment, so you don't have to write JSON:

    ```bash
    FULLAUTH_ORIGINS=https://app.example.com,https://m.example.com
    FULLAUTH_TRUSTED_PROXY_HEADERS=X-Forwarded-For
    ```

    The JSON-array form (`["https://app.example.com"]`) still works for values that need it.

### Generating a secret key

```bash
fullauth secret
```

Prints a random key suitable for `FULLAUTH_SECRET_KEY`. The `fullauth` command ships
with the package.

### Precedence

pydantic-settings resolves values in this order, first wins:

1. Init kwargs: `FullAuthConfig(SECRET_KEY="...")`
2. Process environment: `os.environ["FULLAUTH_SECRET_KEY"]`
3. `.env` file
4. Field defaults

So anything you export in your shell, in `uvicorn --env-file`, or in Docker `env_file:` overrides the dotfile. The dotfile is only read if the variable isn't already in `os.environ`.

### Using a different file

Pass `_env_file` at construction:

```python
FullAuthConfig(_env_file=".env.production")
```

Or subclass once in your app:

```python
from fastapi_fullauth import FullAuthConfig
from pydantic_settings import SettingsConfigDict

class AppFullAuthConfig(FullAuthConfig):
    model_config = SettingsConfigDict(
        env_prefix="FULLAUTH_",
        case_sensitive=True,
        env_file=".env.local",
        extra="ignore",
    )
```

### Cloud / container deployments

You don't need to change anything. Managed platforms (FastAPI Cloud, Fly, Railway, Render), Docker, and Kubernetes inject config as real environment variables; those end up in `os.environ` inside the container. The `.env` default simply doesn't find a file to read and falls through to the process env. No overhead, no surprises.

If you want to be defensively explicit that no file is ever read, pass `FullAuthConfig(_env_file=None)`; but it's not required.

## Reference

### Core

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `SECRET_KEY` | `str \| None` | `None` | JWT signing key. Auto-generated in dev if not set. |
| `ALGORITHM` | `str` | `"HS256"` | JWT signing algorithm. |

### Tokens

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `30` | Access token lifetime. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `30` | Refresh token lifetime. |
| `REFRESH_TOKEN_ROTATION` | `bool` | `True` | Issue new refresh token on each refresh. |
| `JWT_LEEWAY_SECONDS` | `int` | `30` | Tolerance (seconds) for clock drift between client and server when validating `exp`/`iat`. |
| `PASSWORD_RESET_EXPIRE_MINUTES` | `int` | `15` | Password-reset token lifetime. Kept short; independent of `ACCESS_TOKEN_EXPIRE_MINUTES`. |
| `EMAIL_VERIFY_EXPIRE_MINUTES` | `int` | `1440` | Email-verification token lifetime (24 h). |

### Passwords

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PASSWORD_HASH_ALGORITHM` | `"argon2id" \| "bcrypt"` | `"argon2id"` | Hashing algorithm. |
| `PASSWORD_MIN_LENGTH` | `int` | `8` | Minimum password length. |

### Login

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `LOGIN_FIELD` | `str` | `"email"` | Field used for login (`"email"`, `"username"`, etc.). |
| `LOCKOUT_ENABLED` | `bool` | `True` | Enable account lockout after failed login attempts. |
| `LOCKOUT_BACKEND` | `"memory" \| "redis"` | `"memory"` | Lockout storage backend. Use `"redis"` for multi-worker deployments. |
| `MAX_LOGIN_ATTEMPTS` | `int` | `5` | Failed attempts before account lockout. |
| `LOCKOUT_DURATION_MINUTES` | `int` | `15` | Lockout duration after max attempts. |

### Rate Limiting

Per-route auth rate limits are baked into the routers. Global request-rate
middleware (`RateLimitMiddleware`) is opt-in; import it from
`fastapi_fullauth.middleware` and call `app.add_middleware(...)` yourself.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `RATE_LIMIT_BACKEND` | `"memory" \| "redis"` | `"memory"` | Backend used by `AuthRateLimiter` and `create_rate_limiter()`. Use `"redis"` in production; `"memory"` is per-process, so the effective limit is multiplied by the worker count. |
| `TRUSTED_PROXY_HEADERS` | `list[str]` | `[]` | Headers to read real client IP from (e.g. `["X-Forwarded-For"]`). |
| `AUTH_RATE_LIMIT_ENABLED` | `bool` | `True` | Enable per-route auth rate limits. |
| `AUTH_RATE_LIMITS` | `AuthRateLimits` | see below | Per-route request caps: `login=5`, `register=3`, `password_reset=3`, `passkey_auth=10`, `refresh=30`. |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `int` | `60` | Rate limit window in seconds. |

Override individual routes without touching the others. In Python, pass an
`AuthRateLimits` (importable from `fastapi_fullauth`); unset fields keep their
defaults:

```python
from fastapi_fullauth import AuthRateLimits, FullAuthConfig

config = FullAuthConfig(AUTH_RATE_LIMITS=AuthRateLimits(login=10, refresh=60))
```

From the environment, set the field as a JSON object (only the keys you want to
change):

```bash
FULLAUTH_AUTH_RATE_LIMITS='{"login": 10, "refresh": 60}'
```

### Redis

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `REDIS_URL` | `str \| None` | `None` | Redis connection URL. Required when using Redis backends. Setting it switches all subsystems to Redis unless `BACKEND` or an individual `*_BACKEND` is explicitly set to `memory`. |

### Token Blacklist

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `BLACKLIST_ENABLED` | `bool` | `True` | Check blacklist on token decode. |
| `BLACKLIST_BACKEND` | `"memory" \| "redis"` | `"memory"` | Blacklist storage backend. Use `"redis"` in production; `"memory"` is per-process, so a token revoked on one worker remains usable on others (logout won't actually revoke). |

### Middleware

`init_app()` does not wire middleware automatically. Import what you need from
`fastapi_fullauth.middleware` (`SecurityHeadersMiddleware`, `CSRFMiddleware`,
`RateLimitMiddleware`) and `app.add_middleware(...)` it yourself.

`CSRFMiddleware` takes its signing key directly; there's no config field for it.
Pass `config.SECRET_KEY` (≥ 32 chars), or a dedicated key if you want to rotate
it independently:

```python
app.add_middleware(CSRFMiddleware, secret=config.SECRET_KEY)
```

### Cookies

Cookie attributes live on the `CookieBackend` constructor (the cookie backend
is opt-in), not on `FullAuthConfig`. Pass them when you wire it up:

```python
from fastapi_fullauth.backends import CookieBackend

backend = CookieBackend(
    config,
    name="fullauth_access",   # default
    secure=True,              # default
    httponly=True,            # default
    samesite="lax",           # default
    domain=None,              # default
)
fullauth = FullAuth(config=config, adapter=adapter, backends=[backend])
```

### OAuth

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `OAUTH_STATE_EXPIRE_SECONDS` | `int` | `300` | OAuth state token TTL (5 min). |
| `OAUTH_AUTO_LINK_BY_EMAIL` | `bool` | `True` | Auto-link OAuth accounts to existing users by email. |
| `OAUTH_PKCE_ENABLED` | `bool` | `True` | Send PKCE (S256) on providers that support it (Google, GitHub). |
| `PREVENT_REGISTRATION_ENUMERATION` | `bool` | `False` | When `True`, `/register` always returns `202` + a generic message whether or not the email is already registered; an attacker can't use registration responses to probe the user table. Opt-in because the default `201` + user / `409` conflict behavior is simpler for client apps. |

### Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `API_PREFIX` | `str` | `"/api/v1"` | URL prefix for all routes. |
| `AUTH_ROUTER_PREFIX` | `str` | `"/auth"` | Auth router sub-prefix. |
| `ROUTER_TAGS` | `list[str]` | `["Auth"]` | OpenAPI tags for auth routes. |

### Passwords

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PREVENT_LOGIN_TIMING_ATTACKS` | `bool` | `False` | Run a dummy password hash on failed lookups to mask response time. Prevents email enumeration via timing. |

### Global defaults

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `BACKEND` | `str` | `"memory"` | Default backend for all subsystems (blacklist, lockout, rate limit, challenge store). Individual `*_BACKEND` settings override this. Left unset, it follows `REDIS_URL`: `redis` when a URL is set, `memory` otherwise. |
| `ORIGINS` | `list[str]` | `[]` | Default origins list. Propagates to `PASSKEY_ORIGINS` if not explicitly set. |

!!! tip
    Setting `FULLAUTH_REDIS_URL=redis://...` switches all subsystems to Redis at once; you don't also need `FULLAUTH_BACKEND=redis`. Override individual backends as needed (e.g. `LOCKOUT_BACKEND=memory` for local dev), or set `FULLAUTH_BACKEND=memory` to keep everything in-memory despite the URL.

### Passkeys

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PASSKEY_ENABLED` | `bool` | `False` | Enable passkey (WebAuthn) routes. Inferred `True` when `PASSKEY_RP_ID` is set; set it to `False` explicitly to configure passkeys but keep the routes off. |
| `PASSKEY_RP_ID` | `str \| None` | `None` | Relying Party ID (your domain, e.g. `"example.com"`). Setting it turns passkeys on. |
| `PASSKEY_RP_NAME` | `str \| None` | `None` | Relying Party display name (e.g. `"My App"`). |
| `PASSKEY_ORIGINS` | `list[str]` | `[]` | Allowed origins (e.g. `["https://example.com", "https://m.example.com"]`). |
| `PASSKEY_CHALLENGE_BACKEND` | `"memory" \| "redis"` | `"memory"` | Challenge store backend. Use `"redis"` in production; `"memory"` is per-process and breaks under `uvicorn --workers N` (begin and complete can land on different workers). |
| `PASSKEY_CHALLENGE_TTL` | `int` | `60` | Challenge expiry in seconds. |
| `PASSKEY_REQUIRE_USER_VERIFICATION` | `bool` | `True` | Require user verification (PIN/biometric) on register and authenticate. Set `False` only if you need to allow silent authenticators. |

## Production example

A realistic `.env` file for a production deployment:

```bash
# .env.production
FULLAUTH_SECRET_KEY=your-32-char-secret-generated-by-secrets-module
FULLAUTH_ALGORITHM=HS256

# Tokens
FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=15
FULLAUTH_REFRESH_TOKEN_EXPIRE_DAYS=7

# All protection subsystems use Redis (REDIS_URL alone is enough)
FULLAUTH_REDIS_URL=redis://redis:6379/0

# Password hashing
FULLAUTH_PASSWORD_HASH_ALGORITHM=argon2id
FULLAUTH_PASSWORD_MIN_LENGTH=10

# Lockout
FULLAUTH_MAX_LOGIN_ATTEMPTS=5
FULLAUTH_LOCKOUT_DURATION_MINUTES=15

# Rate limiting (per-route caps as a JSON object; unset keys keep defaults)
FULLAUTH_AUTH_RATE_LIMITS={"login": 10}
FULLAUTH_AUTH_RATE_LIMIT_WINDOW_SECONDS=60

# Routing
FULLAUTH_API_PREFIX=/api/v1

# Proxy (if behind Nginx/Cloudflare)
FULLAUTH_TRUSTED_PROXY_HEADERS=["X-Forwarded-For"]
```
