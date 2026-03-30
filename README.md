# fastapi-fullauth

Production-grade, async-native authentication and authorization library for FastAPI.

## Features

- **JWT authentication** with access/refresh token rotation and blacklisting
- **Cookie & Bearer backends** — pluggable transport strategy
- **Brute-force protection** — progressive lockout after failed attempts
- **Password hashing** — Argon2id by default
- **ORM-agnostic** — bring your own database via the adapter interface
- **FastAPI-native** — `Depends()` helpers, pre-built router, Pydantic models throughout

### Adapters (install only what you need)

| Extra | What it adds |
|-------|-------------|
| `[sqlalchemy]` | SQLAlchemy async adapter |
| `[sqlmodel]` | SQLModel adapter |

## Installation

```bash
pip install fastapi-fullauth
# or with an adapter:
pip install fastapi-fullauth[sqlalchemy]
pip install fastapi-fullauth[sqlmodel]
```

## Quick Start

```python
from fastapi import Depends, FastAPI
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import current_user

app = FastAPI()

fullauth = FullAuth(
    config=FullAuthConfig(SECRET_KEY="your-secret-key"),
    adapter=InMemoryAdapter(),
)
fullauth.init_app(app)


@app.get("/me")
async def me(user=Depends(current_user)):
    return user
```

That gives you these endpoints out of the box:

| Endpoint | Description |
|----------|-------------|
| `POST /auth/register` | Create a new user |
| `POST /auth/login` | Get access + refresh tokens |
| `POST /auth/logout` | Blacklist current token |
| `POST /auth/refresh` | Rotate token pair |
| `POST /auth/password-reset/request` | Request a reset token |
| `POST /auth/password-reset/confirm` | Set new password |
| `POST /auth/verify-email/request` | Send verification email |
| `POST /auth/verify-email/confirm` | Verify email address |

## Protecting Routes

```python
from fastapi_fullauth.dependencies import current_user, require_role, require_permission

@app.get("/me")
async def me(user=Depends(current_user)):
    return user

@app.delete("/admin/users/{id}")
async def delete_user(user=Depends(require_role("admin"))):
    ...

@app.post("/posts/{id}/publish")
async def publish(user=Depends(require_permission("posts:publish"))):
    ...
```

## Configuration

All config is via `FullAuthConfig` which reads from environment variables with the `FULLAUTH_` prefix:

```python
FullAuthConfig(
    SECRET_KEY="...",                    # required
    ALGORITHM="HS256",                   # JWT algorithm
    ACCESS_TOKEN_EXPIRE_MINUTES=30,
    REFRESH_TOKEN_EXPIRE_DAYS=30,
    PASSWORD_HASH_ALGORITHM="argon2id",  # or "bcrypt"
    MAX_LOGIN_ATTEMPTS=5,
    LOCKOUT_DURATION_MINUTES=15,
    BLACKLIST_ENABLED=True,
)
```

Or set them as env vars: `FULLAUTH_SECRET_KEY`, `FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES`, etc.

## Custom User Fields

Subclass `UserSchema` and your ORM model to add custom fields:

```python
from fastapi_fullauth.types import UserSchema
from fastapi_fullauth.adapters.sqlalchemy.models import UserModel
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

# 1. extend the schema
class MyUserSchema(UserSchema):
    phone: str | None = None
    display_name: str | None = None

# 2. extend the ORM model
class MyUser(UserModel):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    phone: Mapped[str] = mapped_column(String(20), nullable=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=True)

# 3. pass both to the adapter
adapter = SQLAlchemyAdapter(
    session_maker=session_maker,
    user_schema=MyUserSchema,
    user_model=MyUser,
)
```

Custom fields will flow through `current_user` and all other dependencies automatically.

## Custom Adapter

Implement `AbstractUserAdapter` to plug in any database:

```python
from fastapi_fullauth.adapters.base import AbstractUserAdapter

class MyAdapter(AbstractUserAdapter):
    async def get_user_by_id(self, user_id: str) -> UserSchema | None: ...
    async def get_user_by_email(self, email: str) -> UserSchema | None: ...
    async def create_user(self, data, hashed_password: str) -> UserSchema: ...
    # ... see base.py for the full interface
```

## Middleware

```python
from fastapi_fullauth.middleware import SecurityHeadersMiddleware, CSRFMiddleware
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware

# auto-inject security headers (HSTS, X-Frame-Options, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# CSRF protection (for cookie-based auth)
app.add_middleware(CSRFMiddleware, secret="your-csrf-secret")

# rate limiting (per-IP, in-memory)
app.add_middleware(RateLimitMiddleware, max_requests=60, window_seconds=60)
```

## Alembic Migrations

Add two lines to your `env.py` and fullauth tables will be picked up by `alembic revision --autogenerate`:

```python
from fastapi_fullauth.migrations import include_fullauth_models

include_fullauth_models("sqlalchemy")  # or "sqlmodel"
```

## Development

```bash
# clone and install
git clone https://github.com/mdfarhankc/fastapi-fullauth.git
cd fastapi-fullauth
uv sync --dev --extra sqlalchemy --extra sqlmodel

# lint
uv run ruff check .
uv run ruff format --check .

# run tests
uv run pytest tests/ -v

# run example app
uv run uvicorn examples.basic_app:app --reload
```

## Requirements

- Python >= 3.10
- FastAPI >= 0.110
- Pydantic >= 2.0

## License

MIT
