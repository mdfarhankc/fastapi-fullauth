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
# with OAuth2 social login:
pip install fastapi-fullauth[sqlmodel,oauth]
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

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()

fullauth = FullAuth(
    secret_key="...",
    adapter=SQLModelAdapter(session_maker, user_model=MyUser),
)
```

No need to create separate schema classes or subclass the adapter. Registration and response schemas pick up `display_name` and `phone` automatically. You can still pass explicit `user_schema` / `create_user_schema` if you want full control.

## Protected routes

Use the `Annotated` types for clean route signatures:

```python
from fastapi_fullauth.dependencies import CurrentUser, VerifiedUser, SuperUser, require_role

@app.get("/profile")
async def profile(user: CurrentUser):
    return user

@app.get("/dashboard")
async def dashboard(user: VerifiedUser):
    # only email-verified users
    return {"email": user.email}

@app.delete("/admin/users/{id}")
async def delete_user(user: SuperUser):
    # only superusers
    ...

# or use require_role for custom roles
from fastapi import Depends
from fastapi_fullauth.dependencies import require_role

@app.get("/editor")
async def editor_panel(user=Depends(require_role("editor"))):
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

## Custom token claims

Embed app-specific data into JWTs (available in `payload.extra`):

```python
async def add_claims(user):
    return {"tenant_id": "acme", "plan": "pro"}

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    on_create_token_claims=add_claims,
)
```

Reserved keys (`sub`, `exp`, `iat`, `jti`, `type`, `roles`, `extra`, `family_id`) are rejected to prevent accidental overwrites.

## Password hashing

Argon2id by default. Switch to bcrypt via config:

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    password_hash_algorithm="bcrypt",  # requires: pip install bcrypt
)
```

When switching algorithms, existing users are transparently rehashed on their next login.

## OAuth2 social login

Add Google and/or GitHub login with a few config lines:

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    oauth_providers={
        "google": {
            "client_id": "your-google-client-id",
            "client_secret": "your-google-secret",
            "redirect_uris": [
                "http://localhost:3000/auth/callback",
                "https://myapp.com/auth/callback",
                "myapp://auth/callback",  # Flutter deep link
            ],
        },
        "github": {
            "client_id": "your-github-client-id",
            "client_secret": "your-github-secret",
            "redirect_uri": "http://localhost:3000/auth/callback",  # single URI also works
        },
    },
)
```

This registers these routes automatically:

- `GET /auth/oauth/providers` — list configured providers
- `GET /auth/oauth/{provider}/authorize?redirect_uri=...` — get the authorization URL (optional `redirect_uri` param, validated against allowed list, defaults to first)
- `POST /auth/oauth/{provider}/callback` — exchange code for JWT tokens
- `GET /auth/oauth/accounts` — list linked OAuth accounts
- `DELETE /auth/oauth/accounts/{provider}` — unlink a provider

Users can link multiple providers and keep email/password login alongside OAuth. New users are auto-created on first OAuth login, and existing users are auto-linked by email.

Requires `httpx`: `pip install fastapi-fullauth[oauth]`

## Route control

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    enabled_routes=["login", "logout", "refresh"],
)
```

## Middleware

SecurityHeaders, CSRF, and rate limiting are auto-wired from config flags. Pass `auto_middleware=False` to `init_app()` to handle it yourself.

## Auth rate limiting

Login, register, and password-reset have per-IP rate limits enabled by default (5/3/3 per minute). Configure via `AUTH_RATE_LIMIT_*` settings.

## Login field

By default, login uses `email`. Change it to any field on your user model:

```python
# username login: POST /login {"username": "john", "password": "..."}
fullauth = FullAuth(secret_key="...", adapter=adapter, login_field="username")

# phone login: POST /login {"phone": "+1234567890", "password": "..."}
fullauth = FullAuth(secret_key="...", adapter=adapter, login_field="phone")
```

The Swagger UI and request body update automatically. The adapter looks up users by that field.

## Development

```bash
git clone https://github.com/mdfarhankc/fastapi-fullauth.git
cd fastapi-fullauth
uv sync --dev --extra sqlalchemy --extra sqlmodel
uv run pytest tests/ -v

# run examples
uv run uvicorn examples.memory_app.main:app --reload
uv run uvicorn examples.sqlmodel_app.main:app --reload
```

## License

MIT
