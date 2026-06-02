# Getting started with fastapi-fullauth

This is the "from an empty directory to running auth" walkthrough. Follow it end-to-end or jump to a section.

## 1. Install

```bash
uv add fastapi-fullauth
uv add 'fastapi-fullauth[sqlmodel]'   # or [sqlalchemy]; pick one
```

Optional extras, only pulled in if you opt into those features:

- `fastapi-fullauth[oauth]`: `httpx` for OAuth provider calls
- `fastapi-fullauth[passkey]`: `webauthn>=2` for passkey/WebAuthn
- `fastapi-fullauth[redis]`: `redis` client for production backends

Python floor is 3.10.

## 2. Define your tables

Each library table is a **mixin** you combine with `table=True` (SQLModel) or your own `DeclarativeBase` (SQLAlchemy). Only define the ones you actually need; features you don't opt into never get a table.

```python
# models.py
from sqlmodel import Field, Relationship
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class User(UserMixin, table=True):
    display_name: str | None = Field(default=None, max_length=80)
    refresh_tokens: list[RefreshToken] = Relationship()
```

Add more tables when you turn on a feature:

```python
from fastapi_fullauth.models.sqlmodel import (
    OAuthAccountMixin, PasskeyMixin, PermissionMixin,
    RoleMixin, RolePermissionMixin, UserRoleMixin,
)


class Role(RoleMixin, table=True): pass
class UserRole(UserRoleMixin, table=True): pass
class Permission(PermissionMixin, table=True): pass
class RolePermission(RolePermissionMixin, table=True): pass
class OAuthAccount(OAuthAccountMixin, table=True): pass
class Passkey(PasskeyMixin, table=True): pass
```

The SQLAlchemy variant is the same shape; import from `fastapi_fullauth.models.sqlalchemy` and combine each mixin with your own `class Base(DeclarativeBase): pass`.

## 3. Wire it up

Pass every concrete class you defined to the adapter. The adapter uses `user_model` and `refresh_token_model` for the core flows; the rest are required only if you call into the matching feature (roles, permissions, OAuth, passkey).

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter

from models import RefreshToken, User

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/app")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
)
fullauth = FullAuth(config=FullAuthConfig(), adapter=adapter)

app = FastAPI()
fullauth.init_app(app)
```

`FullAuthConfig()` reads settings from environment variables with the `FULLAUTH_` prefix, plus a `.env` file in the current working directory if present. At minimum set `FULLAUTH_SECRET_KEY`: a 32+ char random string.

Precedence: init kwargs → `os.environ` → `.env` → field defaults. Read a different file via `FullAuthConfig(_env_file=".env.local")`. On cloud platforms (FastAPI Cloud, Docker, Kubernetes) you don't need to do anything; their env vars go into `os.environ` and the `.env` default is a no-op when the file isn't in the container.

## 4. Routes you get for free

With `init_app(app)` and no exclusions:

- `POST /api/v1/auth/register`: create account
- `POST /api/v1/auth/login`: get access + refresh tokens
- `POST /api/v1/auth/refresh`: rotate tokens
- `POST /api/v1/auth/logout`: revoke refresh, blacklist access
- `GET /api/v1/auth/me`: current user
- `PATCH /api/v1/auth/me`: update profile
- `POST /api/v1/auth/change-password`: change while authenticated
- `POST /api/v1/auth/password-reset/{request,confirm}`: reset via email
- `POST /api/v1/auth/verify/{request,confirm}`: verify email
- Admin, OAuth, passkey routes: only if the matching adapter mixin is present and the matching config is enabled

API prefix is `FULLAUTH_API_PREFIX` (default `/api/v1`), auth sub-prefix is `FULLAUTH_AUTH_ROUTER_PREFIX` (default `/auth`).

## 5. Selecting which routers to mount

```python
fullauth.init_app(app, include_routers=["auth", "profile", "verify"])
```

`include_routers=None` (default) registers everything available. Valid names: `"auth"`, `"profile"`, `"verify"`, `"admin"`, `"oauth"`, `"passkey"`. Unknown names raise `ValueError` at init.

## 6. Protecting your own routes

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, require_role, require_permission

@app.get("/things")
async def list_things(user=Depends(current_user)):
    return [...]

@app.delete("/things/{id}", dependencies=[Depends(require_role("admin"))])
async def delete_thing(id: int):
    ...

@app.post("/posts", dependencies=[Depends(require_permission("posts:create"))])
async def create_post():
    ...
```

`require_role` / `require_permission` return dependency callables. Superusers bypass both. The user schema needs a `roles: list[str]` attribute for `require_role` to work; add it if you use RBAC, leave it off otherwise.

## 7. Custom token claims

```python
async def claims(user):
    return {"tenant_id": str(user.tenant_id)}

fullauth = FullAuth(config=..., adapter=..., on_create_token_claims=claims)
```

The function runs on login / refresh. Reserved keys (`sub`, `exp`, `iat`, `jti`, `type`, `roles`, `extra`, `family_id`) raise at construction; you can't shadow them.

## 8. Migrations

Your `app/models/` package owns every table; `Base.metadata` (SQLAlchemy) or `SQLModel.metadata` is the source of truth. In Alembic's `env.py`:

```python
import app.models  # noqa: F401; registers all your tables
from app.core.db import Base   # your project's DeclarativeBase

target_metadata = Base.metadata
```

Features you didn't subclass (e.g. `PasskeyMixin`) aren't in `metadata` and don't show up in autogen diffs.

## 9. Extending `UserSchema`

```python
from fastapi_fullauth import FullAuthConfig
from fastapi_fullauth.types import UserSchema, CreateUserSchema

class MyUser(UserSchema):
    roles: list[str] = []
    display_name: str | None = None

class MyCreateUser(CreateUserSchema):
    display_name: str | None = None

fullauth = FullAuth(
    config=FullAuthConfig(),
    adapter=SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        user_schema=MyUser,
        create_user_schema=MyCreateUser,
    ),
)
```

The schemas flow through `response_model=` and dependency injection. Existing route-handler signatures widen to your subclass automatically via generics.

## 10. First request

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "content-type: application/json" \
  -d '{"email":"a@b.com","password":"correct horse battery staple"}'

curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "content-type: application/json" \
  -d '{"email":"a@b.com","password":"correct horse battery staple"}'
# → {"access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 1800}

curl http://localhost:8000/api/v1/auth/me \
  -H "authorization: Bearer $ACCESS"
```

## Gotchas you'll hit

- **`response_model` vs return type.** Keep both on route handlers. Pydantic v2's Rust serializer uses the annotation; `response_model=` drives OpenAPI. Dropping the annotation silently slows serialization.
- **Refresh token rotation** is on by default. Reusing a token (or a concurrent refresh attempt) revokes the whole token family and returns 401. Good default; just know it's there.
- **Cookie login backend is opt-in.** Default is `BearerBackend`. To ship a cookie-based session, pass `backends=[CookieBackend(config)]` to `FullAuth(...)`.
- **Email verification is not enforced on login.** The library marks users verified when they click the link; gating login on `is_verified` is your call; check `user.is_verified` in a dependency.
- **Do not push to main directly in this repo.** Convention is branch + PR + CI.

See `production.md` for what changes when you ship.
