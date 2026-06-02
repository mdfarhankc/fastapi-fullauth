# Troubleshooting

## Common errors

### "FullAuth not initialized on app.state"

A dependency tried to access the FullAuth instance before it was bound to the app.

**Fix:** Make sure `fullauth.init_app(app)` (or `fullauth.bind(app)`) runs before the app starts handling requests.

```python
auth = FullAuth(adapter=adapter, config=config)
auth.init_app(app)  # must happen before requests
```

If you're using composable routers without `init_app()`, call `bind()` first:

```python
auth.bind(app)
app.include_router(auth.auth_router, prefix="/api/v1/auth")
```

### "SECRET_KEY must be at least 32 characters"

Your secret key is too short. Generate a secure one:

```bash
fullauth secret
```

Set it via environment variable or config:

```bash
export FULLAUTH_SECRET_KEY="your-generated-key-here"
```

### "REDIS_URL must be set when *_BACKEND='redis'"

You set a backend to `"redis"` but didn't provide a Redis connection URL.

```bash
export FULLAUTH_REDIS_URL="redis://localhost:6379"
```

### Tokens don't survive server restarts

You're using the auto-generated `SECRET_KEY`. When the server restarts, a new key is generated and all existing tokens become invalid.

**Fix:** Set an explicit `FULLAUTH_SECRET_KEY` environment variable.

### "Token has expired" on every request

Check clock synchronization between the server and client. The library allows `JWT_LEEWAY_SECONDS` (default 30) of clock skew tolerance. If your clocks are further apart, increase the leeway or fix the clock.

Also check that `ACCESS_TOKEN_EXPIRE_MINUTES` isn't set to an extremely short value.

### Rate limiting doesn't work across workers

The in-memory rate limiter is per-process. Under `uvicorn --workers N`, each worker has its own counter.

**Fix:** Set `FULLAUTH_RATE_LIMIT_BACKEND=redis` and configure `FULLAUTH_REDIS_URL`. Or set `FULLAUTH_BACKEND=redis` to switch all subsystems at once.

### Token blacklisting doesn't work across workers

Same issue as rate limiting. The in-memory blacklist is per-process. A token blacklisted on worker 1 stays valid on worker 2.

**Fix:** Set `FULLAUTH_BLACKLIST_BACKEND=redis`.

### CSRF token mismatch

The `CSRFMiddleware` uses a double-submit cookie pattern. The frontend must:

1. Read the `fullauth_csrf` cookie value
2. Send it as the `X-CSRF-Token` header on state-changing requests (POST, PUT, DELETE, PATCH)

```javascript
const csrfToken = document.cookie
    .split("; ")
    .find(row => row.startsWith("fullauth_csrf="))
    ?.split("=")[1];

fetch("/api/v1/auth/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    credentials: "include",
});
```

Also check that `cookie_domain`, `cookie_samesite`, and `cookie_secure` settings match between the CSRF middleware and your deployment.

### Passkey begin/complete fails in production

The challenge store defaults to in-memory. If the `begin` and `complete` requests land on different workers, the challenge is lost.

**Fix:** Set `FULLAUTH_PASSKEY_CHALLENGE_BACKEND=redis`.

### "Invalid OAuth state token"

The OAuth state token has a 5-minute TTL (`OAUTH_STATE_EXPIRE_SECONDS`). This error means:

- The user took too long on the provider's login page, or
- The `SECRET_KEY` differs between the server that generated the state and the one handling the callback (happens under multi-worker deployments with auto-generated keys)

**Fix:** Set an explicit `FULLAUTH_SECRET_KEY`.

### "Adapter does not support passkeys" (or OAuth, or roles)

Your adapter class doesn't inherit the required mixin. Check that:

- For passkeys: your adapter inherits `PasskeyAdapterMixin` and you passed `passkey_model=` to the constructor
- For OAuth: your adapter inherits `OAuthAdapterMixin` and you passed `oauth_account_model=` to the constructor
- For roles/admin: your adapter inherits `RoleAdapterMixin` and you passed `role_model=` to the constructor

### Registration always returns 202 with "Registration received"

`PREVENT_REGISTRATION_ENUMERATION` is enabled. This is intentional: it prevents attackers from probing which emails are registered. Both successful and duplicate registrations return the same 202 response.

If you want the normal 201/409 behavior, set `FULLAUTH_PREVENT_REGISTRATION_ENUMERATION=false`.

### Password change fails for OAuth-only users

OAuth-only users don't have a password hash. When changing password for the first time, omit the `current_password` field. The library skips the current password check for users without an existing password.

## Logging

The library logs to loggers under the `fastapi_fullauth` namespace:

| Logger | What it logs |
|--------|-------------|
| `fastapi_fullauth` | General initialization warnings |
| `fastapi_fullauth.login` | Login attempts, failures, rehashing |
| `fastapi_fullauth.logout` | Logout events, ownership mismatches |
| `fastapi_fullauth.tokens` | Token creation, blacklisting |
| `fastapi_fullauth.hooks` | Hook execution failures |
| `fastapi_fullauth.passkey` | Passkey registration and authentication |
| `fastapi_fullauth.challenges` | Challenge store operations |
| `fastapi_fullauth.routers.passkey` | Passkey route errors |
| `fastapi_fullauth.routers.oauth` | OAuth route errors |

To see debug output, configure logging in your app:

```python
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger("fastapi_fullauth").setLevel(logging.DEBUG)
```

## Getting help

- [GitHub Issues](https://github.com/mdfarhankc/fastapi-fullauth/issues) for bug reports and feature requests
- [Documentation](https://mdfarhankc.github.io/fastapi-fullauth/) for guides and API reference
