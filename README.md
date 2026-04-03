# fastapi-fullauth

Production-grade, async-native authentication and authorization library for FastAPI.

## Features

- **JWT authentication** with access/refresh token rotation and blacklisting
- **Cookie & Bearer backends** — pluggable transport strategy
- **Brute-force protection** — progressive lockout after failed attempts
- **Password hashing** — Argon2id by default
- **ORM-agnostic** — bring your own database via the adapter interface
- **Auto-derived schemas** — define your model, get registration + response schemas for free
- **Auto-wired middleware** — security headers, CSRF, rate limiting from config flags
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
from fastapi import FastAPI
from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.memory import InMemoryAdapter

app = FastAPI()

fullauth = FullAuth(
    secret_key="your-secret-key",
    adapter=InMemoryAdapter(),
)
fullauth.init_app(app)
```

That gives you these endpoints out of the box:

| Endpoint | Description |
|----------|-------------|
| `GET  /api/v1/auth/me` | Get current user |
| `POST /api/v1/auth/register` | Create a new user |
| `POST /api/v1/auth/login` | Get access + refresh tokens |
| `POST /api/v1/auth/logout` | Blacklist current token |
| `POST /api/v1/auth/refresh` | Rotate token pair |
| `POST /api/v1/auth/password-reset/request` | Request a reset token |
| `POST /api/v1/auth/password-reset/confirm` | Set new password |
| `POST /api/v1/auth/verify-email/request` | Send verification email |
| `POST /api/v1/auth/verify-email/confirm` | Verify email address |
| `POST /api/v1/auth/admin/assign-role` | Assign role to user (superuser only) |
| `POST /api/v1/auth/admin/remove-role` | Remove role from user (superuser only) |

> **Dev mode:** Omit `secret_key` and a random key is auto-generated with a console warning. Tokens will invalidate on restart — set `FULLAUTH_SECRET_KEY` for production.

## Protecting Routes

A `/me` endpoint is included automatically. For custom protected routes, use the dependency helpers:

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, require_role, require_permission

@app.get("/profile")
async def profile(user=Depends(current_user)):
    return user

@app.delete("/admin/users/{id}")
async def delete_user(user=Depends(require_role("admin"))):
    ...

@app.post("/posts/{id}/publish")
async def publish(user=Depends(require_permission("posts:publish"))):
    ...
```

All dependencies return a typed `UserSchema` for IDE autocompletion.

## Configuration

Pass config inline or via a `FullAuthConfig` object — pick whichever fits:

```python
# Inline (simple)
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    api_prefix="/api/v2",
    access_token_expire_minutes=60,
)

# Full config object (power users)
from fastapi_fullauth import FullAuthConfig

fullauth = FullAuth(
    config=FullAuthConfig(
        SECRET_KEY="...",
        ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        REFRESH_TOKEN_EXPIRE_DAYS=30,
        PASSWORD_HASH_ALGORITHM="argon2id",
        MAX_LOGIN_ATTEMPTS=5,
        LOCKOUT_DURATION_MINUTES=15,
        BLACKLIST_ENABLED=True,
        API_PREFIX="/api/v1",
        AUTH_ROUTER_PREFIX="/auth",
        ROUTER_TAGS=["Auth"],
        INJECT_SECURITY_HEADERS=True,
        CSRF_ENABLED=False,
        RATE_LIMIT_ENABLED=False,
    ),
    adapter=adapter,
)
```

Or set them as env vars: `FULLAUTH_SECRET_KEY`, `FULLAUTH_ACCESS_TOKEN_EXPIRE_MINUTES`, etc.

## Custom User Fields

Define your model — schemas are **auto-derived**. No manual schema classes or adapter subclassing needed.

### SQLModel

```python
from fastapi_fullauth.adapters.sqlmodel import UserBase, Role, UserRoleLink, RefreshTokenRecord, SQLModelAdapter
from sqlmodel import Field, Relationship

class MyUser(UserBase, table=True):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(back_populates="users", link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship(back_populates="user")

# That's it — UserSchema and CreateUserSchema are auto-derived from MyUser
fullauth = FullAuth(
    secret_key="...",
    adapter=SQLModelAdapter(session_maker, user_model=MyUser),
)
```

### SQLAlchemy

```python
from fastapi_fullauth.adapters.sqlalchemy import UserModel, SQLAlchemyAdapter
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

class MyUser(UserModel):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    phone: Mapped[str] = mapped_column(String(20), nullable=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=True)

fullauth = FullAuth(
    secret_key="...",
    adapter=SQLAlchemyAdapter(session_maker, user_model=MyUser),
)
```

### Explicit schemas (if you need full control)

You can still pass explicit schemas to override auto-derivation:

```python
from fastapi_fullauth.types import CreateUserSchema, UserSchema

class MyCreateSchema(CreateUserSchema):
    display_name: str

class MyUserSchema(UserSchema):
    display_name: str = ""

fullauth = FullAuth(
    secret_key="...",
    adapter=SQLModelAdapter(session_maker, user_model=MyUser, user_schema=MyUserSchema),
    create_user_schema=MyCreateSchema,
)
```

## Custom Token Claims

Inject extra data into JWT tokens:

```python
async def build_claims(user):
    return {"org_id": "org-123", "plan": "pro"}

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    on_create_token_claims=build_claims,
)
# tokens now contain {sub, exp, ..., extra: {org_id: "org-123", plan: "pro"}}
```

Claims are embedded on both login and token refresh.

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

## Event Hooks

React to auth events with async callbacks:

```python
async def welcome_email(user):
    await send_email(user.email, "Welcome!")

async def log_login(user):
    print(f"{user.email} logged in")

fullauth.hooks.on("after_register", welcome_email)
fullauth.hooks.on("after_login", log_login)
fullauth.hooks.on("after_logout", lambda user_id: print(f"{user_id} logged out"))
```

Supported events: `after_register`, `after_login`, `after_logout`, `after_password_reset`, `after_email_verify`

## Email Callbacks

Plug in your own email sending — via constructor params or hooks:

```python
# Via constructor
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    on_send_verification_email=send_verify,
    on_send_password_reset_email=send_reset,
)

# Or via hooks (equivalent)
fullauth.hooks.on("send_verification_email", send_verify)
fullauth.hooks.on("send_password_reset_email", send_reset)
```

Both receive `(email: str, token: str)`.

## Password Validation

Configure password strength rules:

```python
from fastapi_fullauth import PasswordValidator

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    password_validator=PasswordValidator(
        min_length=12,
        require_uppercase=True,
        require_digit=True,
        require_special=True,
        blocked_passwords=["password123", "qwerty123"],
    ),
)
```

Applied on both registration and password reset.

## Disable Routes

Only enable the routes you need — use the `Route` enum for type safety:

```python
from fastapi_fullauth import Route

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    enabled_routes=[Route.LOGIN, Route.LOGOUT, Route.REFRESH],
)
```

Route names: `Route.ME`, `Route.REGISTER`, `Route.LOGIN`, `Route.LOGOUT`, `Route.REFRESH`, `Route.VERIFY_EMAIL`, `Route.PASSWORD_RESET`

Bare strings still work: `enabled_routes=["login", "logout"]`

## Login Response With User

Include user data alongside tokens in the login response:

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    include_user_in_login=True,
)
# POST /auth/login returns: {access_token, refresh_token, token_type, user: {...}}
```

## Middleware

Middleware is **auto-wired** by `init_app()` based on config flags:

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    inject_security_headers=True,   # on by default
    csrf_enabled=True,
    rate_limit_enabled=True,
)
fullauth.init_app(app)  # SecurityHeaders + CSRF + RateLimit added automatically
```

To skip auto-wiring and add middleware manually:

```python
fullauth.init_app(app, auto_middleware=False)

from fastapi_fullauth.middleware import SecurityHeadersMiddleware, CSRFMiddleware
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware, secret="your-csrf-secret")
app.add_middleware(RateLimitMiddleware, max_requests=60, window_seconds=60)
```

## Utilities

```python
from fastapi_fullauth import create_superuser, generate_secret_key

# generate a secure secret key
key = generate_secret_key()

# create a superuser (use in a setup script)
user = await create_superuser(adapter, email="admin@example.com", password="securepass")
# user is auto-verified and marked as superuser
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

# run example apps
uv run uvicorn examples.memory_app:app --reload
uv run uvicorn examples.sqlalchemy_app:app --reload
uv run uvicorn examples.sqlmodel_app:app --reload
```

## Requirements

- Python >= 3.10
- FastAPI >= 0.110
- Pydantic >= 2.0

## License

MIT
