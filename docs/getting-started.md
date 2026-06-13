# Getting Started

This guide walks through setting up fastapi-fullauth from scratch.

## Installation

```bash
pip install fastapi-fullauth[sqlmodel]
```

## 1. Define your tables

Each library table is a **mixin** you combine with `table=True` (SQLModel) or your own `DeclarativeBase` (SQLAlchemy). Subclass only the ones you need; features you don't opt into never register a table.

```python
# models.py
from sqlmodel import Field, Relationship
from fastapi_fullauth.models.sqlmodel import (
    RefreshTokenMixin, RoleMixin, UserMixin, UserRoleMixin,
)


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class Role(RoleMixin, table=True):
    pass


class UserRole(UserRoleMixin, table=True):
    pass


class User(UserMixin, table=True):
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)
    roles: list[Role] = Relationship(link_model=UserRole)
    refresh_tokens: list[RefreshToken] = Relationship()
```

`UserMixin` provides `id`, `email`, `hashed_password` (nullable; `NULL` for OAuth-only users), `is_active`, `is_verified`, `is_superuser`, and `created_at`. Add any extra fields you need.

!!! note
    Define your own schemas extending `UserSchema` and `CreateUserSchema` to include custom fields like `display_name` and `phone`, then pass them to the adapter. See [Custom Schemas](adapters/index.md#custom-schemas) or the [API Reference](api-reference.md).

## 2. Set up the database

```python
# config.py
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DATABASE_URL = "sqlite+aiosqlite:///app.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)
```

## 3. Configure FullAuth

```python
# auth.py
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter

from .config import session_maker
from .models import RefreshToken, Role, User, UserRole

fullauth = FullAuth(
    adapter=SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        role_model=Role,
        user_role_model=UserRole,
    ),
    config=FullAuthConfig(
        SECRET_KEY="your-secret-key-at-least-32-bytes",
    ),
)
```

!!! tip
    Omit `SECRET_KEY` during development and a random one is generated automatically. Tokens won't survive restarts, but it's convenient for dev.

## 4. Wire it into FastAPI

```python
# main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlmodel import SQLModel

from .auth import fullauth
from .config import engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await fullauth.aclose()
    await engine.dispose()

app = FastAPI(lifespan=lifespan)
fullauth.init_app(app)
```

`init_app()`'s shutdown handler does not run under a custom `lifespan`, so call `await fullauth.aclose()` yourself to release pooled Redis connections and OAuth HTTP clients.

That's it. Start the server and you have a full auth system:

```bash
uvicorn main:app --reload
```

### Composable routers

`init_app()` registers every available router by default. Pass `include_routers` to opt in to a subset:

```python
# only auth + profile, skip everything else
fullauth.init_app(app, include_routers=["auth", "profile"])
```

For full manual control, wire individual routers yourself:

```python
app = FastAPI(lifespan=lifespan)
fullauth.bind(app)  # required for dependencies to work

app.include_router(fullauth.auth_router, prefix="/api/v1/auth")
app.include_router(fullauth.profile_router, prefix="/api/v1/auth")
```

### Middleware

`init_app()` does not add any middleware; import what you need from `fastapi_fullauth.middleware` and add it yourself:

```python
from fastapi_fullauth.middleware import (
    SecurityHeadersMiddleware,
    CSRFMiddleware,
    RateLimitMiddleware,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware, secret=fullauth.config.SECRET_KEY)
app.add_middleware(RateLimitMiddleware, max_requests=60, window_seconds=60)
```

| Router | Routes |
|--------|--------|
| `auth_router` | register, login, logout, refresh |
| `profile_router` | me, verified-me, update profile, delete account, change password |
| `verify_router` | email verification, password reset |
| `admin_router` | assign/remove roles and permissions (superuser) |
| `sessions_router` | list active sessions, revoke one, revoke others |
| `oauth_router` | OAuth provider routes (only if configured) |
| `passkey_router` | Passkey register, authenticate, list, delete (only if enabled) |

## 5. Try it out

**Register:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

**Login:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": { "id": "…", "email": "user@example.com", "is_active": true, "is_verified": false, "is_superuser": false }
}
```

`user` contains the full user object on every successful login.

**Get current user:**

```bash
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer eyJ..."
```

## 6. Add protected routes

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth import UserSchema
from fastapi_fullauth.dependencies import current_user, current_active_verified_user, require_role

CurrentUser = Annotated[UserSchema, Depends(current_user)]
VerifiedUser = Annotated[UserSchema, Depends(current_active_verified_user)]

@app.get("/profile")
async def profile(user: CurrentUser):
    return user

@app.get("/dashboard")
async def dashboard(user: VerifiedUser):
    return {"email": user.email}

@app.get("/admin")
async def admin(user=Depends(require_role("admin"))):
    return {"msg": "admin area"}
```

See [Protected Routes](auth/dependencies.md) for all dependency types.

## What to read next

- **[Architecture](architecture.md)**: understand how the library works (tokens, adapters, protection layers)
- **[Configuration](configuration.md)**: all config options with production examples
- **[OAuth2 Social Login](oauth.md)**: add Google/GitHub login
- **[Passkeys](passkeys.md)**: passwordless login with biometrics
- **[Event Hooks](auth/hooks.md)**: send emails, log events, sync external systems
- **[Rate Limiting](security/rate-limiting.md)**: protect your endpoints
- **[Testing](testing.md)**: test your auth-protected routes
- **[Troubleshooting](troubleshooting.md)**: common errors and solutions
