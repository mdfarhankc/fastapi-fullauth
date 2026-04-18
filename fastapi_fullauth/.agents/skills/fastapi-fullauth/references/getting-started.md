# Getting started with fastapi-fullauth

This is the "from an empty directory to running auth" walkthrough. Follow it end-to-end or jump to a section.

## 1. Install

```bash
uv add fastapi-fullauth
uv add 'fastapi-fullauth[sqlmodel]'   # or [sqlalchemy] — pick one
```

Optional extras, only pulled in if you opt into those features:

- `fastapi-fullauth[oauth]` — `httpx` for OAuth provider calls
- `fastapi-fullauth[passkey]` — `webauthn>=2` for passkey/WebAuthn
- `fastapi-fullauth[redis]` — `redis` client for production backends

Python floor is 3.10.

## 2. Define your `User` model

Inherit from `UserBase` (or `UserModel` for SQLAlchemy). You can add any columns — the adapter passes them through.

```python
# models.py
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase
from sqlmodel import Field

class User(UserBase, table=True):
    __tablename__ = "users"

    display_name: str | None = Field(default=None, max_length=80)
```

Important: importing `.models.base` registers only the user + refresh-token tables. If you want roles, permissions, OAuth accounts, or passkey credentials as tables, import the corresponding submodule:

```python
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink  # noqa: F401
from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord  # noqa: F401
from fastapi_fullauth.adapters.sqlmodel.models.passkey import PasskeyRecord  # noqa: F401
```

This "import what you want" pattern is deliberate — apps that don't need OAuth never get an OAuth table.

## 3. Wire it up

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

from models import User

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/app")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
fullauth = FullAuth(config=FullAuthConfig(), adapter=adapter)

app = FastAPI()
fullauth.init_app(app)
```

`FullAuthConfig()` reads settings from environment variables with the `FULLAUTH_` prefix (via pydantic-settings). At minimum set `FULLAUTH_SECRET_KEY` — a 32+ char random string.

## 4. Routes you get for free

With `init_app(app)` and no exclusions:

- `POST /api/v1/auth/register` — create account
- `POST /api/v1/auth/login` — get access + refresh tokens
- `POST /api/v1/auth/refresh` — rotate tokens
- `POST /api/v1/auth/logout` — revoke refresh, blacklist access
- `GET /api/v1/auth/me` — current user
- `PATCH /api/v1/auth/me` — update profile
- `POST /api/v1/auth/change-password` — change while authenticated
- `POST /api/v1/auth/password-reset/{request,confirm}` — reset via email
- `POST /api/v1/auth/verify/{request,confirm}` — verify email
- Admin, OAuth, passkey routes — only if the matching adapter mixin is present and the matching config is enabled

API prefix is `FULLAUTH_API_PREFIX` (default `/api/v1`), auth sub-prefix is `FULLAUTH_AUTH_ROUTER_PREFIX` (default `/auth`).

## 5. Dropping routers you don't need

```python
fullauth.init_app(app, exclude_routers=["admin", "oauth"])
```

Valid names: `"auth"`, `"profile"`, `"verify"`, `"admin"`, `"oauth"`, `"passkey"`. Unknown names raise `ValueError` at init.

## 6. Protecting your own routes

```python
from fastapi_fullauth.dependencies import current_user, require_role, require_permission

@app.get("/things")
async def list_things(user=current_user):
    return [...]

@app.delete("/things/{id}", dependencies=[require_role("admin")])
async def delete_thing(id: int):
    ...

@app.post("/posts", dependencies=[require_permission("posts:create")])
async def create_post():
    ...
```

`require_role` / `require_permission` return dependency callables. Superusers bypass both. The user schema needs a `roles: list[str]` attribute for `require_role` to work — add it if you use RBAC, leave it off otherwise.

## 7. Custom token claims

```python
async def claims(user):
    return {"tenant_id": str(user.tenant_id)}

fullauth = FullAuth(config=..., adapter=..., on_create_token_claims=claims)
```

The function runs on login / refresh. Reserved keys (`sub`, `exp`, `iat`, `jti`, `type`, `roles`, `extra`, `family_id`) raise at construction — you can't shadow them.

## 8. Migrations

`fastapi_fullauth.migrations.include_fullauth_models("sqlmodel", include=["base", "role", "oauth"])` in your Alembic `env.py` imports only the model groups you use. Autogenerate picks them up; models you don't list aren't in `MetaData` and don't show up in diffs.

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
- **Email verification is not enforced on login.** The library marks users verified when they click the link; gating login on `is_verified` is your call — check `user.is_verified` in a dependency.
- **Do not push to main directly in this repo.** Convention is branch + PR + CI.

See `production.md` for what changes when you ship.
