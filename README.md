# fastapi-fullauth

[![PyPI](https://img.shields.io/pypi/v/fastapi-fullauth)](https://pypi.org/project/fastapi-fullauth/)
[![Python](https://img.shields.io/pypi/pyversions/fastapi-fullauth)](https://pypi.org/project/fastapi-fullauth/)
[![CI](https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml/badge.svg)](https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Async auth library for FastAPI. Handles JWT tokens, refresh rotation, password hashing, email verification, and role-based access out of the box.

## Install

```bash
pip install fastapi-fullauth
# with an ORM adapter:
pip install fastapi-fullauth[sqlmodel]
pip install fastapi-fullauth[sqlalchemy]
# with redis for token blacklisting:
pip install fastapi-fullauth[sqlmodel,redis]
```

## Quick start

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

This gives you `/auth/me`, `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/change-password`, `/auth/password-reset/*`, `/auth/verify-email/*`, and admin role management endpoints — all under `/api/v1` by default.

Omit `secret_key` in dev and a random one is generated (tokens won't survive restarts).

## Custom user fields

Just define your model — schemas are auto-derived:

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

fullauth = FullAuth(
    secret_key="...",
    adapter=SQLModelAdapter(session_maker, user_model=MyUser),
)
```

No need to create separate schema classes or subclass the adapter. Registration and response schemas pick up `display_name` and `phone` automatically. You can still pass explicit `user_schema` / `create_user_schema` if you want full control.

## Protected routes

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, require_role

@app.get("/profile")
async def profile(user=Depends(current_user)):
    return user

@app.delete("/admin/users/{id}")
async def delete_user(user=Depends(require_role("admin"))):
    ...
```

## Configuration

Pass inline kwargs or a full config object:

```python
# inline
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    api_prefix="/api/v2",
    access_token_expire_minutes=60,
)

# or use FullAuthConfig for everything
from fastapi_fullauth import FullAuthConfig
fullauth = FullAuth(config=FullAuthConfig(SECRET_KEY="..."), adapter=adapter)
```

Config also reads env vars with `FULLAUTH_` prefix.

## Redis blacklist

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    blacklist_backend="redis",
    redis_url="redis://localhost:6379/0",
)
```

## Refresh token security

Refresh tokens are stored in DB with family tracking. If a revoked token is replayed (possible theft), the entire token family gets revoked. Disable rotation with `REFRESH_TOKEN_ROTATION=False`.

## Event hooks

```python
async def welcome(user):
    await send_email(user.email, "Welcome!")

fullauth.hooks.on("after_register", welcome)
```

Events: `after_register`, `after_login`, `after_logout`, `after_password_change`, `after_password_reset`, `after_email_verify`, `send_verification_email`, `send_password_reset_email`

## Route control

```python
from fastapi_fullauth import Route

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    enabled_routes=[Route.LOGIN, Route.LOGOUT, Route.REFRESH],
)
```

## Middleware

SecurityHeaders, CSRF, and rate limiting are auto-wired from config flags. Pass `auto_middleware=False` to `init_app()` to handle it yourself.

## Auth rate limiting

Login, register, and password-reset have per-IP rate limits enabled by default (5/3/3 per minute). Configure via `AUTH_RATE_LIMIT_*` settings.

## Development

```bash
git clone https://github.com/mdfarhankc/fastapi-fullauth.git
cd fastapi-fullauth
uv sync --dev --extra sqlalchemy --extra sqlmodel
uv run pytest tests/ -v
```

## License

MIT
