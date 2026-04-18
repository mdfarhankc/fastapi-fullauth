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

### Passwords

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PASSWORD_HASH_ALGORITHM` | `"argon2id" \| "bcrypt"` | `"argon2id"` | Hashing algorithm. |
| `PASSWORD_MIN_LENGTH` | `int` | `8` | Minimum password length. |

### Login

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `LOGIN_FIELD` | `str` | `"email"` | Field used for login (`"email"`, `"username"`, etc.). |
| `INCLUDE_USER_IN_LOGIN` | `bool` | `False` | Include user object in login/OAuth callback response. |
| `LOCKOUT_ENABLED` | `bool` | `True` | Enable account lockout after failed login attempts. |
| `LOCKOUT_BACKEND` | `"memory" \| "redis"` | `"memory"` | Lockout storage backend. Use `"redis"` for multi-worker deployments. |
| `MAX_LOGIN_ATTEMPTS` | `int` | `5` | Failed attempts before account lockout. |
| `LOCKOUT_DURATION_MINUTES` | `int` | `15` | Lockout duration after max attempts. |

### Rate Limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `bool` | `False` | Enable global rate limit middleware. |
| `RATE_LIMIT_BACKEND` | `"memory" \| "redis"` | `"memory"` | Rate limiter storage backend. |
| `TRUSTED_PROXY_HEADERS` | `list[str]` | `[]` | Headers to read real client IP from (e.g. `["X-Forwarded-For"]`). |
| `AUTH_RATE_LIMIT_ENABLED` | `bool` | `True` | Enable per-route auth rate limits. |
| `AUTH_RATE_LIMIT_LOGIN` | `int` | `5` | Max login attempts per window. |
| `AUTH_RATE_LIMIT_REGISTER` | `int` | `3` | Max registrations per window. |
| `AUTH_RATE_LIMIT_PASSWORD_RESET` | `int` | `3` | Max password reset requests per window. |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `int` | `60` | Rate limit window in seconds. |

### Redis

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `REDIS_URL` | `str \| None` | `None` | Redis connection URL. Required when using Redis backends. |

### Token Blacklist

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `BLACKLIST_ENABLED` | `bool` | `True` | Check blacklist on token decode. |
| `BLACKLIST_BACKEND` | `"memory" \| "redis"` | `"memory"` | Blacklist storage backend. |

### Middleware

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `INJECT_SECURITY_HEADERS` | `bool` | `True` | Auto-add security headers middleware. |
| `CSRF_ENABLED` | `bool` | `False` | Auto-add CSRF middleware. |
| `CSRF_SECRET` | `str \| None` | `None` | CSRF signing secret. Falls back to `SECRET_KEY`. |

### Cookies

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `COOKIE_NAME` | `str` | `"fullauth_access"` | Access token cookie name. |
| `COOKIE_SECURE` | `bool` | `True` | Set Secure flag on cookies. |
| `COOKIE_HTTPONLY` | `bool` | `True` | Set HttpOnly flag on cookies. |
| `COOKIE_SAMESITE` | `"lax" \| "strict" \| "none"` | `"lax"` | SameSite cookie policy. |
| `COOKIE_DOMAIN` | `str \| None` | `None` | Cookie domain. |

### OAuth

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `OAUTH_STATE_EXPIRE_SECONDS` | `int` | `300` | OAuth state token TTL (5 min). |
| `OAUTH_AUTO_LINK_BY_EMAIL` | `bool` | `True` | Auto-link OAuth accounts to existing users by email. |

### Routing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `API_PREFIX` | `str` | `"/api/v1"` | URL prefix for all routes. |
| `AUTH_ROUTER_PREFIX` | `str` | `"/auth"` | Auth router sub-prefix. |
| `ROUTER_TAGS` | `list[str]` | `["Auth"]` | OpenAPI tags for auth routes. |

### Passkeys

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PASSKEY_ENABLED` | `bool` | `False` | Enable passkey (WebAuthn) routes. |
| `PASSKEY_RP_ID` | `str \| None` | `None` | Relying Party ID (your domain, e.g. `"example.com"`). |
| `PASSKEY_RP_NAME` | `str \| None` | `None` | Relying Party display name (e.g. `"My App"`). |
| `PASSKEY_ORIGINS` | `list[str]` | `[]` | Allowed origins (e.g. `["https://example.com", "https://m.example.com"]`). |
| `PASSKEY_CHALLENGE_BACKEND` | `"memory" \| "redis"` | `"memory"` | Challenge store backend. |
| `PASSKEY_CHALLENGE_TTL` | `int` | `60` | Challenge expiry in seconds. |
| `PASSKEY_REQUIRE_USER_VERIFICATION` | `bool` | `True` | Require user verification (PIN/biometric) on register and authenticate. Set `False` only if you need to allow silent authenticators. |
