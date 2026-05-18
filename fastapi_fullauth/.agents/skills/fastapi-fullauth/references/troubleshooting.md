# Troubleshooting

Common errors and warnings, what they mean, and what to change.

## Startup warnings

### `FULLAUTH_SECRET_KEY is not set. A random key has been generated. Tokens will be invalidated on restart.`

You didn't set `FULLAUTH_SECRET_KEY`. Fine for dev; **broken for prod and for multi-worker even in dev**. Set a long random value in env:

```bash
export FULLAUTH_SECRET_KEY="$(openssl rand -hex 32)"
```

### `In-memory backends in use: BLACKLIST_BACKEND, LOCKOUT_BACKEND, ...`

One or more of `BLACKLIST_BACKEND`, `LOCKOUT_BACKEND`, `RATE_LIMIT_BACKEND`, `PASSKEY_CHALLENGE_BACKEND` is `"memory"`. State is per-process. Under `uvicorn --workers N`:

- Blacklist → logout silently broken across workers
- Lockout → effective threshold multiplied by worker count
- Rate limit → effective limit multiplied by worker count
- Passkey challenge → register/begin and register/complete on different workers fail

Set them to `"redis"` (and configure `REDIS_URL`) in production. See `production.md`.

## Runtime errors

### `ValueError: Challenge expired or invalid` on `/passkeys/register/complete` or `/authenticate/complete`

Most likely causes:

1. **Multi-worker + memory challenge store** — begin/complete hit different workers. Switch `PASSKEY_CHALLENGE_BACKEND` to `"redis"`.
2. **Challenge TTL too short** — `PASSKEY_CHALLENGE_TTL=60` default, user took longer than a minute between options and assertion. Bump to 300 or so for slow UX paths.
3. **The `challenge_key` from begin wasn't passed back to complete** — frontend bug, check the request body.

### `AttributeError: 'UserSchema' object has no attribute 'roles'` from `require_role`

Your `UserSchema` doesn't have a `roles: list[str]` field. The default doesn't include it on purpose (apps without RBAC shouldn't carry dead fields). Extend:

```python
from pydantic import Field
from fastapi_fullauth.types import UserSchema

class MyUser(UserSchema):
    roles: list[str] = Field(default_factory=list)
```

And pass `MyUser` to both `SQLModelAdapter(user_schema=MyUser)` and (if generic) the `FullAuth` construction.

### `MissingGreenlet` / "greenlet_spawn has not been called"

SQLAlchemy async + a relationship with `lazy="select"` (the default) = runtime error the first time you touch the attribute. The built-in adapters call `selectinload(User.roles)` themselves, so the `roles` relationship on your user model is fine either way. For any other relationship you add (custom user fields, joined tables outside the auth surface), one of:

- Set `lazy="selectin"` on the relationship definition.
- At query time, add `options(selectinload(Model.relation))`.

### `401 Could not validate credentials` when the password is correct

Several possibilities (they all produce this one generic response, which is by design):

- **Account is locked** after too many failed attempts. Wait `LOCKOUT_DURATION_MINUTES` (default 15) or have an admin clear it via `adapter.lockout.clear(identifier)`.
- **Wrong email case** pre-v0.9 — now fixed; emails are normalised.
- **Token expired** — front end should handle `401` by calling `/refresh`.
- **Clock drift** between services triggered `JWT_LEEWAY_SECONDS` rejection. Default is 30 s; bump if you have wider drift.
- **`SECRET_KEY` changed between worker restart and the token's issue time** — tokens become invalid. Not a bug, consequence of ephemeral keys.

### `401 — refresh token reuse/concurrent use — revoking family`

The refresh endpoint detected a refresh token being used more than once (or used concurrently by multiple clients). Causes:

- **Actual reuse attack** — someone got the refresh token from logs, browser extensions, etc., and used it after the legitimate user rotated it.
- **Client bug** — same refresh token sent twice because the client didn't persist the new one returned on rotation.
- **Concurrent refreshes** from multiple tabs / devices racing.

The whole token family is revoked on detection — the user has to log in again. Usually a client bug in practice; check that your frontend stores and uses the new refresh token from each `/refresh` response.

### `ImportError: webauthn package is required`

`PASSKEY_ENABLED=True` but the `[passkey]` extra isn't installed:

```bash
uv add 'fastapi-fullauth[passkey]'
```

### `ValueError: REDIS_URL must be set when ..._BACKEND='redis'`

You set `BLACKLIST_BACKEND=redis` (or any other) without `REDIS_URL`. Configure both:

```bash
export FULLAUTH_REDIS_URL="redis://localhost:6379/0"
```

### `UserAlreadyExistsError` during a race

Two concurrent `/register` requests for the same email. The adapter catches `IntegrityError` from the unique constraint and translates it — one succeeds, the other gets a clean 409. Handled; not a bug unless you see 500s.

### `ValueError: PASSKEY_RP_ID required when PASSKEY_ENABLED=True`

`PASSKEY_ENABLED=True` needs both `PASSKEY_RP_ID` (bare hostname) and `PASSKEY_ORIGINS` (list of full origins). Example:

```bash
export FULLAUTH_PASSKEY_RP_ID=app.example.com
export FULLAUTH_PASSKEY_ORIGINS='["https://app.example.com"]'
```

### Logout doesn't actually log the user out

Known causes:

- **In-memory blacklist with multi-worker** — revoked token still valid on other workers. Switch `BLACKLIST_BACKEND=redis`.
- **Cookie backend + mismatched attributes** — fixed in 0.9; before that, `delete_cookie` didn't match `secure`/`samesite` and the browser silently ignored it. Upgrade.
- **Using bearer tokens and not refreshing** — logout blacklists the access token's `jti`. The client still has the token; the server now rejects it. If the client doesn't check and keeps using it, it'll eventually get a 401. That's expected.

## Configuration warnings you can ignore

- **`SettingsConfigDict extra="ignore"`** — intentional so stray `FULLAUTH_*` env vars in your `.env` (e.g. from a shared dev infra env file) don't fail config construction.
- **`FullAuthConfig reads .env by default`** — `env_file=".env"` is the default since 0.8. If your container doesn't have `.env`, it's a silent no-op.

## When to file a bug vs a support question

File a bug if:

- Behavior contradicts what the reference files say.
- A committed test fails on a supported Python / DB combination.
- A security contract is broken (UV bypass, sign-count downgrade, token reuse not detected, etc.).

Before filing, try to produce a minimal reproducer against `tests/conftest.py`-style fixtures. Most issues turn out to be adapter contract violations in custom code (CAS return types, session lifecycle, email normalisation) — check those first.
