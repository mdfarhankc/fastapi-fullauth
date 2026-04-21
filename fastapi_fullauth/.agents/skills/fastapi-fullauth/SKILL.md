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
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase

class User(UserBase, table=True):
    __tablename__ = "users"

engine = create_async_engine("postgresql+asyncpg://...")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

fullauth = FullAuth(
    config=FullAuthConfig(),   # reads FULLAUTH_* env vars
    adapter=SQLModelAdapter(session_maker=session_maker, user_model=User),
)

app = FastAPI()
fullauth.init_app(app)         # routers + middleware in one call
```

That exposes `/api/v1/auth/{register,login,logout,refresh}`, `/api/v1/auth/me`, and more. See `references/getting-started.md` for a runnable walkthrough.

## Things to get right on day one

1. **`FULLAUTH_SECRET_KEY` must be set in production.** If unset, the library auto-generates one and emits a `UserWarning`. That means tokens invalidate on every restart — fine for dev, broken for prod.
2. **`init_app` / `init_middleware` are idempotent** since v0.8.0 — calling either twice warns and no-ops. Pick one wiring style and stick with it.
3. **In-memory backends are single-process.** `BLACKLIST_BACKEND`, `LOCKOUT_BACKEND`, `RATE_LIMIT_BACKEND`, `PASSKEY_CHALLENGE_BACKEND` all default to `"memory"` — the library emits a startup `UserWarning` listing which ones you're using. Switch to `"redis"` before `uvicorn --workers N` or you get revoked-tokens-that-still-work, halved rate limits, and broken passkey begin/complete pairs.
4. **Routers are opt-in.** `init_app(app, exclude_routers=["admin", "oauth"])` drops what you don't need. Admin/OAuth/passkey routers **auto-skip** when your adapter doesn't implement the matching mixin, so a minimal adapter doesn't accidentally expose routes it can't back.
5. **Don't add `roles: list[str]` to your custom `UserSchema` unless you actually use roles.** The default schema is intentionally minimal — no forced columns, no forced routes.

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
- **`references/migrations.md`** — Alembic `env.py` wiring, `include_fullauth_models` helper, v0.7 → v0.8 schema step.
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
