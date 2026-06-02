# Architecture

This page explains how fastapi-fullauth works internally. Read it to understand how the components connect before diving into specific features.

## Overview

The library is built around a central `FullAuth` class that composes several subsystems. Here's how a request flows through the system:

```
Request
  |
  v
[Middleware]          SecurityHeaders, CSRF, RateLimitMiddleware (optional, user-added)
  |
  v
[Router endpoint]    /login, /register, /me, /refresh, etc.
  |
  v
[Dependencies]       current_user, require_role, require_permission
  |
  v
[Token Engine]       decode JWT, check blacklist, verify signature
  |
  v
[Adapter]            get_user_by_id, get_user_roles, store_refresh_token
  |
  v
[Database]           SQLModel / SQLAlchemy / custom backend
```

The `FullAuth` class ties everything together: it holds the adapter, token engine, protection subsystems, and event hooks. Dependencies access it via `app.state.fullauth`.

## The FullAuth orchestrator

When you create a `FullAuth` instance, it initializes several components:

```python
auth = FullAuth(
    adapter=adapter,        # database backend
    config=config,          # FullAuthConfig settings
    providers=[google],     # OAuth providers (optional)
    backends=[BearerBackend()],  # token transport (default: bearer)
)
```

At construction time, FullAuth creates:

- A **TokenEngine** with a token blacklist (in-memory or Redis)
- A **LockoutManager** for brute-force protection
- An **AuthRateLimiter** with per-route sliding windows
- A **ChallengeStore** for passkey flows (if `PASSKEY_ENABLED=True`)
- Lazy-loaded router properties for each route group

### init_app vs bind

`init_app(app)` is the standard setup path. It calls `bind(app)` internally, builds the combined router from all sub-routers, and includes it on the app:

```python
auth.init_app(app)
```

`bind(app)` only sets `app.state.fullauth` without adding any routers. Use it when you want to wire routers manually:

```python
auth.bind(app)
app.include_router(auth.auth_router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(auth.profile_router, prefix="/api/v1/auth", tags=["Auth"])
```

### Why middleware isn't auto-wired

Middleware is never added by `init_app()`. You add it yourself with `app.add_middleware(...)`. This is deliberate: middleware order matters in FastAPI (they execute in reverse registration order), and implicit wiring hides that from you.

## Adapters and the database layer

### The adapter contract

`AbstractUserAdapter` defines the interface every adapter must implement:

- **User CRUD**: `get_user_by_id()`, `get_user_by_email()`, `create_user()`, `update_user()`, `delete_user()`
- **Password management**: `get_hashed_password()`, `set_password()`
- **Refresh tokens**: `store_refresh_token()`, `get_refresh_token()`, `revoke_refresh_token()`, `revoke_refresh_token_family()`, `revoke_all_user_refresh_tokens()`
- **Verification**: `set_user_verified()`, `get_user_roles()`

The library ships two adapters: `SQLModelAdapter` and `SQLAlchemyAdapter`.

### Mixin architecture

Optional mixins add capabilities to your adapter. The library checks `isinstance()` at startup to decide which routers to mount. If your adapter doesn't inherit a mixin, the corresponding feature is simply not included.

| Mixin | Enables | Required model |
|-------|---------|----------------|
| `RoleAdapterMixin` | Admin router, `require_role()` | `RoleMixin` |
| `PermissionAdapterMixin` | `require_permission()` | `PermissionMixin`, `RolePermissionMixin` |
| `OAuthAdapterMixin` | OAuth router | `OAuthAccountMixin` |
| `PasskeyAdapterMixin` | Passkey router | `PasskeyMixin` |

### Model mixins

The library provides SQLAlchemy declarative mixins for database tables. You subclass them to create concrete tables in your app's metadata:

```python
from fastapi_fullauth.models.sqlmodel import UserMixin

class User(UserMixin, table=True):
    display_name: str | None = None  # your custom fields
```

The library never ships its own metadata registry. Your app owns every table, which means Alembic migrations work naturally.

## Token lifecycle

### Access tokens

Short-lived JWTs (default 30 minutes). They carry the user ID (`sub`), roles, and custom claims in the `extra` field. Verified on every request by checking the signature, expiry, and blacklist.

### Refresh tokens

Long-lived JWTs (default 30 days). Stored in the database and organized into **families**. A family groups all the refresh tokens in a single login session.

### Token pair creation

Login, OAuth callback, and passkey authentication all end with the same `create_token_pair()` call. It returns an access token and a refresh token with a shared `family_id`.

### Refresh token rotation

When `REFRESH_TOKEN_ROTATION=True` (the default), each call to `/refresh`:

1. Atomically revokes the old refresh token using compare-and-swap (`revoke_refresh_token()` returns a bool)
2. If the CAS succeeded (caller won the race), issues a new token pair in the same family
3. If the CAS failed (someone else already revoked it), the entire family is revoked and the request is rejected

This means if two clients race to refresh the same token, the loser's session is terminated. This is the correct behavior: it prevents a stolen token from being usable after the legitimate user refreshes.

### Reuse detection

If a revoked refresh token is replayed (an attacker tries to use a token the user already consumed), the family revocation kicks in. All tokens in that family are revoked, terminating the session entirely.

```
User refreshes token A -> gets token B (A is revoked)
Attacker replays token A -> revoke_refresh_token returns False
  -> entire family revoked (B is now invalid too)
  -> attacker gets nothing, user must re-login
```

### Token blacklisting

Access tokens are blacklisted by their `jti` (unique token ID) on logout. The blacklist entry has a TTL matching the token's remaining lifetime, so entries expire automatically.

Single-use tokens (email verification, password reset) are also blacklisted after consumption to prevent replay.

### Purpose-scoped tokens

Email verification, password reset, and OAuth state tokens are regular access tokens with a `purpose` field in their `extra` claims. The `current_user` dependency explicitly rejects tokens with a purpose field. This prevents someone from using a password reset token to access protected routes.

## Request authentication flow

When a request hits a protected route, here's what happens step by step:

1. **Token extraction**: `_extract_token` checks the `Authorization: Bearer` header first. If not found, it falls back to configured backends (cookie, etc.). If no token is found anywhere, the request gets a 401.

2. **Token decoding**: `decode_token` verifies the JWT signature using `SECRET_KEY`, checks expiry (with `JWT_LEEWAY_SECONDS` tolerance for clock skew), and queries the blacklist.

3. **Type validation**: the dependency checks that `token.type == "access"` (not a refresh token) and that the token has no `purpose` field (not a verification/reset token).

4. **User lookup**: the user is loaded by `sub` (user ID) from the adapter.

5. **Active check**: if the user is inactive (`is_active=False`), the request gets a 401.

6. **Additional checks** (depending on the dependency used):
    - `current_active_verified_user` checks `is_verified`
    - `current_superuser` checks `is_superuser`
    - `require_role()` checks the `roles` claim in the token
    - `require_permission()` resolves permissions through the adapter by looking up the user's roles

## Protection subsystems

### Account lockout

Tracks failed login attempts per identifier (email by default). After `MAX_LOGIN_ATTEMPTS` (default 5) failures, the account is locked for `LOCKOUT_DURATION_MINUTES` (default 15). A successful login clears the counter. Lockout is checked at the start of every login attempt, before any password verification.

### Auth rate limiting

Per-route sliding-window rate limiters, keyed by client IP:

| Route | Default limit | `AUTH_RATE_LIMITS` field |
|-------|:---:|---|
| login | 5/min | `login` |
| register | 3/min | `register` |
| password-reset | 3/min | `password_reset` |
| passkey-authenticate | 10/min | `passkey_auth` |
| refresh | 30/min | `refresh` |

When a limit is exceeded, the route returns 429 with a `Retry-After` header.

### Token blacklist

A jti-based store checked on every `decode_token` call when `BLACKLIST_ENABLED=True`. Entries have a TTL matching the token's remaining lifetime, so the store doesn't grow unbounded.

### Challenge store

Used for passkey (WebAuthn) flows. Stores short-lived nonces that prevent replay attacks. The `pop` operation retrieves and deletes the challenge atomically, ensuring single use.

## Memory vs Redis backends

All four subsystems (blacklist, lockout, rate limiter, challenge store) default to in-memory storage. In-memory is per-process. Under `uvicorn --workers N`, state is not shared between workers:

- A token blacklisted on worker 1 stays valid on worker 2
- Lockout attempt counts don't aggregate across workers
- Rate limit counters reset per worker
- Passkey `begin` and `complete` can land on different workers and the challenge is lost

For production with multiple workers, set `FULLAUTH_BACKEND=redis` and `FULLAUTH_REDIS_URL`:

```bash
export FULLAUTH_BACKEND=redis
export FULLAUTH_REDIS_URL=redis://localhost:6379
```

The `BACKEND` setting propagates to all four subsystems. You can override individual ones if needed (e.g. `BLACKLIST_BACKEND=redis` while keeping `RATE_LIMIT_BACKEND=memory` for local development).

!!! warning
    The library emits a `UserWarning` at startup if any in-memory backends are detected. This is a reminder to switch to Redis before deploying with multiple workers.

## Hooks and extensibility

### Event hooks

`EventHooks` is a simple async event emitter. Register callbacks with `fullauth.hooks.on()`:

```python
async def on_login(user):
    print(f"User {user.email} logged in")

fullauth.hooks.on("after_login", on_login)
```

Hooks fire after the side effect commits. A raising hook is caught and logged; the route returns its normal response. This means auth never returns a 500 because of a notification failure.

There are 10 events: `after_register`, `after_login`, `after_logout`, `after_password_change`, `after_password_reset`, `after_email_verify`, `after_oauth_login`, `after_oauth_register`, `send_verification_email`, `send_password_reset_email`.

See [Event Hooks](auth/hooks.md) for the full list with callback signatures.

### Custom claims

The `on_create_token_claims` callback runs at token creation (login, refresh, OAuth) and embeds data in the JWT's `extra` field:

```python
async def add_claims(user):
    return {"tenant_id": user.tenant_id}

auth = FullAuth(..., on_create_token_claims=add_claims)
```

See [Custom Token Claims](auth/custom-claims.md) for details.

### The get_fullauth dependency

The `get_fullauth` dependency gives users access to the entire `FullAuth` instance from any FastAPI route or dependency. Through it you can reach the adapter, token engine, config, hooks, and every protection subsystem:

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import get_fullauth

async def my_dependency(fullauth=Depends(get_fullauth)):
    user = await fullauth.adapter.get_user_by_id(some_id)
    await fullauth.token_engine.blacklist_token(some_jti)
```

## Composable routers

FullAuth includes six sub-routers:

| Router | Routes | Condition |
|--------|--------|-----------|
| `auth_router` | register, login, refresh, logout | Always included |
| `profile_router` | /me, password change | Always included |
| `verify_router` | Email verify, password reset | Always included |
| `admin_router` | Role/permission management | Adapter inherits `RoleAdapterMixin` |
| `oauth_router` | OAuth authorize/callback | Providers configured and adapter inherits `OAuthAdapterMixin` |
| `passkey_router` | WebAuthn registration/auth | `PASSKEY_ENABLED=True` and adapter inherits `PasskeyAdapterMixin` |

Feature gating is automatic: if your adapter doesn't support a feature, the corresponding router is not mounted. No dead endpoints, no 501 errors for features you didn't set up.

To include only specific routers:

```python
auth.init_app(app, include_routers=["auth", "profile"])
```

Or wire them manually for full control over prefixes and tags:

```python
auth.bind(app)
app.include_router(auth.auth_router, prefix="/auth", tags=["Auth"])
app.include_router(auth.profile_router, prefix="/auth", tags=["Profile"])
```
