---
name: fastapi-fullauth
description: Authoritative guidance for integrating fastapi-fullauth, an async auth library for FastAPI (JWT, OAuth2, passkeys/WebAuthn, RBAC, rate limiting, CSRF). Load when the user imports `fastapi_fullauth`, works with `FullAuth`/`FullAuthConfig`, or asks about auth, login, OAuth, passkeys, roles/permissions, or refresh-token flows in a FastAPI project.
triggers:
  - fastapi-fullauth
  - fastapi_fullauth
  - FullAuth
  - FullAuthConfig
  - PasskeyAdapterMixin
  - from fastapi_fullauth
---

# fastapi-fullauth

Async-first authentication library for FastAPI. Keyword-only public API, composable models and routers — users only pay for what they opt into.

## Shape of a minimal app

```python
from fastapi import FastAPI
from sqlmodel import Relationship
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True): pass

class User(UserMixin, table=True):
    refresh_tokens: list[RefreshToken] = Relationship()


engine = create_async_engine("postgresql+asyncpg://...")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

fullauth = FullAuth(
    config=FullAuthConfig(),   # reads FULLAUTH_* env vars
    adapter=SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
    ),
)

app = FastAPI()
fullauth.init_app(app)         # routers + middleware in one call
```

That exposes `/api/v1/auth/{register,login,logout,refresh}`, `/api/v1/auth/me`, and more. See `references/getting-started.md` for a runnable walkthrough.

## Things to get right on day one

1. **Models are mixins.** Combine `*Mixin` classes from `fastapi_fullauth.models.{sqlalchemy,sqlmodel}` with your own `Base` / `table=True` to declare each table you use. There is no `FullAuthBase` and no concrete `*Model` classes any more — your tables live on your `Base.metadata`. Adapter constructors take each concrete model class as a keyword arg (`user_model=...`, `refresh_token_model=...`, plus `role_model`, `user_role_model`, `permission_model`, `role_permission_model`, `oauth_account_model`, `passkey_model` for the features you use). Calling a feature method without its model raises `RuntimeError`.
2. **`FULLAUTH_SECRET_KEY` must be set in production.** If unset, the library auto-generates one and emits a `UserWarning`. That means tokens invalidate on every restart — fine for dev, broken for prod.
3. **`init_app` is idempotent** since v0.8.0 — calling it twice warns and no-ops. Middleware is **not** wired by `init_app()` in v0.10.0+ — import what you want from `fastapi_fullauth.middleware` (`SecurityHeadersMiddleware`, `CSRFMiddleware`, `RateLimitMiddleware`) and `app.add_middleware(...)` it yourself.
4. **In-memory backends are single-process.** `BLACKLIST_BACKEND`, `LOCKOUT_BACKEND`, `RATE_LIMIT_BACKEND`, `PASSKEY_CHALLENGE_BACKEND` all default to `"memory"` — the library emits a startup `UserWarning` listing which ones you're using. Switch to `"redis"` before `uvicorn --workers N` or you get revoked-tokens-that-still-work, halved rate limits, and broken passkey begin/complete pairs.
5. **Routers are opt-in.** `init_app(app, include_routers=["auth", "profile"])` registers only those; `include_routers=None` (default) registers everything available. Admin/OAuth/passkey routers **auto-skip** when your adapter doesn't implement the matching mixin, so a minimal adapter doesn't accidentally expose routes it can't back.
6. **Don't add `roles: list[str]` to your custom `UserSchema` unless you actually use roles.** The default schema is intentionally minimal — no forced columns, no forced routes.

## Composability matrix

| Feature         | Adapter mixin           | Router          | Extra |
|-----------------|-------------------------|-----------------|-------|
| Core auth       | `AbstractUserAdapter`   | `auth`, `profile`, `verify` | — |
| RBAC            | `RoleAdapterMixin`, `PermissionAdapterMixin` | `admin` | — |
| OAuth           | `OAuthAdapterMixin`     | `oauth`         | `[oauth]` extra, provider config |
| Passkeys        | `PasskeyAdapterMixin`   | `passkey`       | `[passkey]` extra, `PASSKEY_ENABLED=True`, `PASSKEY_RP_ID`, `PASSKEY_ORIGINS` |

Built-in `SQLAlchemyAdapter` and `SQLModelAdapter` inherit all mixins. A custom adapter implements only what its app uses.

## Where to look next

- **`references/getting-started.md`** — project setup from zero: adapter choice, `User` model, wiring, first requests.
- **`references/composable-design.md`** — the opt-in philosophy (models, routers, schemas, mixins); read this if you're extending `UserSchema` or writing a custom adapter.
- **`references/adapters.md`** — built-in and custom adapters, mixin matrix, contracts custom adapters must honour (CAS returns, `IntegrityError` translation).
- **`references/oauth.md`** — provider setup, callback flow, `email_verified` gate on auto-link, writing custom providers.
- **`references/passkeys.md`** — WebAuthn setup, UV enforcement, discoverable credentials, sign-count CAS, challenge store.
- **`references/rbac.md`** — roles + permissions mixins, `require_role` / `require_permission`, admin router, cold-start seeding.
- **`references/hooks.md`** — `after_*` and `send_*` hook signatures, when each fires, gotchas.
- **`references/migrations.md`** — Alembic `env.py` wiring with your own `Base.metadata`, v0.x → v0.10 mixin pivot step.
- **`references/production.md`** — deployment checklist: `SECRET_KEY`, Redis backends, cookie flags, rate-limit trust boundary, observability.
- **`references/testing.md`** — pytest fixture stack, mocking email hooks, minting tokens, exercising passkey / OAuth flows.
- **`references/troubleshooting.md`** — common errors and warnings, what they mean, what to change.
- **`references/api-reference.md`** — single-page lookup: every public import, every config setting, every built-in route.
- **Upstream docs** — full reference at the library's docs site. For LLMs, `docs/llms-full.txt` in the repo is a single-file concatenation of the docs.

## Conventions to preserve when editing this codebase

- Keep return type annotations on route handlers. `response_model=` alone is not enough — Pydantic v2's Rust serializer uses the annotation.
- Adapter methods that are compare-and-swap (e.g. `revoke_refresh_token`, `update_passkey_sign_count`) return `bool`. Custom adapters must honour that — returning `None` silently disables the race detection.
- Commit incrementally. Small, focused commits with a one-line subject describing the behavior change.
- Reach for `uv add` / `uv sync` / `uv run`, not `pip`.
