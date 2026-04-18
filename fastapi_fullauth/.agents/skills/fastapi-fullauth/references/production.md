# Production checklist

What changes between `uv run uvicorn app:app --reload` and "live". Each item below is either a known-sharp-edge or a default that's convenient for dev and wrong for prod.

## 1. `FULLAUTH_SECRET_KEY` is required

Unset → the library generates a random key and emits a `UserWarning`. Every process restart invalidates every issued token. Every worker gets a different key and can't decode tokens issued by another.

```bash
export FULLAUTH_SECRET_KEY="$(openssl rand -hex 32)"
```

Minimum 32 random bytes. Keep it in your secret manager, not the repo.

## 2. Swap every in-memory backend for Redis

The library emits a startup `UserWarning` listing which ones are in-memory. Four settings matter:

```bash
FULLAUTH_REDIS_URL=redis://redis:6379/0
FULLAUTH_BLACKLIST_BACKEND=redis
FULLAUTH_LOCKOUT_BACKEND=redis
FULLAUTH_RATE_LIMIT_BACKEND=redis
FULLAUTH_PASSKEY_CHALLENGE_BACKEND=redis   # only if passkeys are enabled
```

What each one prevents:

- **Blacklist (memory):** `/logout` doesn't actually log the user out on other workers. A revoked token still works on any worker whose memory was untouched.
- **Lockout (memory):** brute-force protection is divided by worker count. N workers = N × configured failure attempts before anyone's locked.
- **Rate limit (memory):** configured limit is per-worker. With 4 workers, 10 req/min effectively becomes 40.
- **Passkey challenge store (memory):** register/begin on worker A stores the challenge only on A. register/complete routed to worker B returns "challenge expired or invalid." Silently broken.

Install the Redis extra: `uv add 'fastapi-fullauth[redis]'`.

## 3. Trust the right proxy headers

Rate limit and lockout are keyed on client IP (`utils.get_client_ip`). Behind a load balancer / CDN, `request.client.host` is the LB — so one proxy IP would eat everyone's budget.

```bash
FULLAUTH_TRUSTED_PROXY_HEADERS=["X-Forwarded-For"]
```

Only set this if you actually trust the upstream to rewrite the header. A public-facing deployment without a reverse proxy should leave this empty — otherwise clients can spoof their IP by sending `X-Forwarded-For` themselves.

## 4. Cookie flags

If you use `CookieBackend` (cookie-based sessions):

```bash
FULLAUTH_COOKIE_SECURE=true             # default — don't change this
FULLAUTH_COOKIE_HTTPONLY=true           # default — don't change this
FULLAUTH_COOKIE_SAMESITE=lax            # or strict if cross-site flows don't apply
FULLAUTH_COOKIE_DOMAIN=app.example.com  # explicit — not a leading dot
```

`SameSite=none` requires `Secure=true` and is only right for cross-origin embeds. For most SPAs on the same domain, `lax` is correct.

## 5. Token lifetimes

```bash
FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=15      # short — rotations are cheap
FULLAUTH_REFRESH_TOKEN_EXPIRE_DAYS=30
FULLAUTH_PASSWORD_RESET_EXPIRE_MINUTES=15    # deliberately short
FULLAUTH_EMAIL_VERIFY_EXPIRE_MINUTES=1440    # 24h
FULLAUTH_JWT_LEEWAY_SECONDS=30               # default is fine
```

`PASSWORD_RESET_EXPIRE_MINUTES` and `EMAIL_VERIFY_EXPIRE_MINUTES` are independent of access-token TTL. Changing the access token for a mobile app doesn't secretly widen the password-reset window.

## 6. CSRF

Only relevant when you use `CookieBackend` — a bearer-token API that isn't sent automatically by browsers doesn't have CSRF exposure in the first place.

```bash
FULLAUTH_CSRF_ENABLED=true
FULLAUTH_CSRF_SECRET=...   # defaults to SECRET_KEY
```

The middleware uses double-submit-cookie: GET plants a signed CSRF cookie, unsafe methods require both the cookie and a matching `X-CSRF-Token` header. The cookie is deliberately not HttpOnly — your JS needs to read it to populate the header. That's the pattern working as intended.

## 7. Passkeys — if enabled

```bash
FULLAUTH_PASSKEY_ENABLED=true
FULLAUTH_PASSKEY_RP_ID=app.example.com                       # bare hostname, no scheme, no path
FULLAUTH_PASSKEY_ORIGINS='["https://app.example.com"]'
FULLAUTH_PASSKEY_REQUIRE_USER_VERIFICATION=true              # default — do not flip to false without a reason
FULLAUTH_PASSKEY_CHALLENGE_BACKEND=redis
FULLAUTH_PASSKEY_CHALLENGE_TTL=60
```

UV enforcement on register AND authenticate is what keeps passkeys as two-factor (device + biometric/PIN). `PASSKEY_REQUIRE_USER_VERIFICATION=false` downgrades them to single-factor for any authenticator that'll sign without prompting the user.

## 8. Database migrations

The library defines its tables via `UserBase`, `RefreshTokenRecord`, and the optional sub-modules (`role`, `permission`, `oauth`, `passkey`). In your Alembic `env.py`:

```python
from fastapi_fullauth.migrations import include_fullauth_models

include_fullauth_models("sqlmodel", include=["base", "role", "oauth"])

target_metadata = SQLModel.metadata
```

`alembic revision --autogenerate -m "..."` will then pick up exactly the groups you listed. Apps that don't use OAuth never get the `fullauth_oauth_accounts` table.

**Since v0.8.0:** the OAuth account model has a new composite unique constraint on `(provider, provider_user_id)`. Existing users upgrading from v0.7.0 should autogenerate a migration to add it before deploying — without it, concurrent OAuth callbacks could have created duplicate-identity rows.

## 9. Rate limit budgets

```bash
FULLAUTH_AUTH_RATE_LIMIT_ENABLED=true     # default
FULLAUTH_AUTH_RATE_LIMIT_LOGIN=5          # per IP per minute
FULLAUTH_AUTH_RATE_LIMIT_REGISTER=3
FULLAUTH_AUTH_RATE_LIMIT_PASSWORD_RESET=3
FULLAUTH_AUTH_RATE_LIMIT_PASSKEY_AUTH=10
FULLAUTH_AUTH_RATE_LIMIT_WINDOW_SECONDS=60
```

These apply per IP. If your app puts its auth routes behind Cloudflare / another WAF that already rate-limits, you can leave these as is — the two layers compose fine.

## 10. Sentry / observability (your responsibility)

The library logs to standard loggers: `fastapi_fullauth.login`, `fastapi_fullauth.oauth`, `fastapi_fullauth.passkey`, etc. Hook your logging framework into those.

Events worth alerting on:

- `refresh token reuse/concurrent use — revoking family` (`fastapi_fullauth.router`) — someone replayed a refresh token, or clock-skew is driving concurrent use into looking like an attack.
- `Passkey authentication failed` (`fastapi_fullauth.router.passkey`)
- `oauth auto-link refused: unverified email on existing account` (`fastapi_fullauth.oauth`) — someone's trying to hijack via unverified provider email.
- `Auth rate limit exceeded` (`fastapi_fullauth.ratelimit`) at sustained volume.

## 11. Idempotent init

Since v0.8.0, `init_app()` and `init_middleware()` both warn and no-op on second call. If you see either warning in your logs, you're wiring twice — check your startup path. Most common cause: moving from `init_app()` to `init_middleware()` during a refactor and leaving both in place.

## 12. Final check before deploy

- [ ] `FULLAUTH_SECRET_KEY` set, long, not in version control
- [ ] All four `*_BACKEND` settings set to `redis` (or whichever custom backend you registered)
- [ ] `REDIS_URL` reachable from every worker
- [ ] `TRUSTED_PROXY_HEADERS` set iff you have a trusted reverse proxy
- [ ] Passkey `RP_ID` and `ORIGINS` are the right domain, not localhost
- [ ] Alembic migration for the OAuth composite unique constraint (if upgrading from ≤ 0.7.0 with OAuth in use)
- [ ] Startup logs show no `UserWarning` about in-memory backends or missing SECRET_KEY
