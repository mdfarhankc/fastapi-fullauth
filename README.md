<p align="center">
  <img src="https://img.icons8.com/fluency/96/shield.png" alt="FastAPI FullAuth" width="96" height="96">
</p>

<h1 align="center">FastAPI FullAuth</h1>

<p align="center">
  <em>Production-grade, async-native authentication and authorization for FastAPI.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/v/fastapi-fullauth?color=009688&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/pyversions/fastapi-fullauth?color=009688" alt="Python"></a>
  <a href="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml"><img src="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-009688" alt="License"></a>
  <a href="https://mdfarhankc.github.io/fastapi-fullauth"><img src="https://img.shields.io/badge/docs-mdfarhankc.github.io-009688" alt="Docs"></a>
</p>

<p align="center">
  <strong>Documentation</strong>: <a href="https://mdfarhankc.github.io/fastapi-fullauth">https://mdfarhankc.github.io/fastapi-fullauth</a>
  <br>
  <strong>Source Code</strong>: <a href="https://github.com/mdfarhankc/fastapi-fullauth">https://github.com/mdfarhankc/fastapi-fullauth</a>
</p>

---

Add a complete authentication and authorization system to your **FastAPI** project. FastAPI FullAuth is designed to be production-ready, async-native, and pluggable — handling JWT tokens, refresh rotation, password hashing, email verification, OAuth2 social login, and role-based access out of the box.

## Features

- **JWT access + refresh tokens** with configurable expiry
- **Refresh token rotation** with reuse detection — revokes entire session family on replay
- **Password hashing** via Argon2id (default) or bcrypt, with transparent rehashing
- **Email verification** and **password reset** flows with event hooks
- **OAuth2 social login** — Google and GitHub, with multi-redirect-URI support
- **Role-based access control** — `CurrentUser`, `VerifiedUser`, `SuperUser`, `require_role()`
- **Rate limiting** — per-route auth limits + global middleware (memory or Redis)
- **CSRF protection** and **security headers** middleware, auto-wired
- **Pluggable adapters** — SQLModel, SQLAlchemy, or in-memory
- **Auto-derived schemas** — custom user fields picked up automatically
- **Event hooks** — `after_register`, `after_login`, `send_verification_email`, etc.
- **Custom JWT claims** — embed app-specific data in tokens
- **Structured logging** — all auth events, security violations, and failures logged
- **Redis support** — token blacklist and rate limiter backends
- **Python 3.10 – 3.14** supported

## Installation

```bash
pip install fastapi-fullauth

# with an ORM adapter
pip install fastapi-fullauth[sqlmodel]
pip install fastapi-fullauth[sqlalchemy]

# with Redis for token blacklisting
pip install fastapi-fullauth[sqlmodel,redis]

# with OAuth2 social login
pip install fastapi-fullauth[sqlmodel,oauth]

# everything
pip install fastapi-fullauth[all]
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

That's it — 15+ auth routes are registered under `/api/v1/auth/` automatically.

Omit `secret_key` in dev and a random one is generated (tokens won't survive restarts).

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create a new user |
| `POST` | `/auth/login` | Authenticate, get tokens |
| `POST` | `/auth/logout` | Blacklist token |
| `POST` | `/auth/refresh` | Rotate token pair |
| `GET` | `/auth/me` | Get current user |
| `GET` | `/auth/me/verified` | Verified users only |
| `PATCH` | `/auth/me` | Update profile |
| `DELETE` | `/auth/me` | Delete account |
| `POST` | `/auth/change-password` | Change password |
| `POST` | `/auth/verify-email/request` | Request verification email |
| `POST` | `/auth/verify-email/confirm` | Confirm email |
| `POST` | `/auth/password-reset/request` | Request password reset |
| `POST` | `/auth/password-reset/confirm` | Reset password |
| `POST` | `/auth/admin/assign-role` | Assign role (superuser) |
| `POST` | `/auth/admin/remove-role` | Remove role (superuser) |

With OAuth enabled, additional routes are registered under `/auth/oauth/`. All routes are prefixed with `/api/v1` by default.

## Custom user fields

Define your model — schemas are auto-derived:

```python
from sqlmodel import Field, Relationship
from fastapi_fullauth.adapters.sqlmodel import (
    UserBase, Role, UserRoleLink, RefreshTokenRecord, SQLModelAdapter,
)

class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()

fullauth = FullAuth(
    secret_key="...",
    adapter=SQLModelAdapter(session_maker, user_model=User),
)
```

Registration and response schemas pick up `display_name` and `phone` automatically. No separate schema classes needed.

## Protected routes

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import CurrentUser, VerifiedUser, SuperUser, require_role

@app.get("/profile")
async def profile(user: CurrentUser):
    return user

@app.get("/dashboard")
async def dashboard(user: VerifiedUser):
    return {"email": user.email}

@app.delete("/admin/users/{id}")
async def delete_user(user: SuperUser):
    ...

@app.get("/editor")
async def editor_panel(user=Depends(require_role("editor"))):
    ...
```

## OAuth2 social login

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
            ],
        },
        "github": {
            "client_id": "your-github-client-id",
            "client_secret": "your-github-secret",
            "redirect_uri": "http://localhost:3000/auth/callback",
        },
    },
)
```

Requires `httpx`: `pip install fastapi-fullauth[oauth]`

## Event hooks

```python
async def welcome(user):
    await send_email(user.email, "Welcome!")

async def send_verify(email, token):
    await send_email(email, f"Verify: https://myapp.com/verify?token={token}")

fullauth.hooks.on("after_register", welcome)
fullauth.hooks.on("send_verification_email", send_verify)
```

Events: `after_register`, `after_login`, `after_logout`, `after_password_change`, `after_password_reset`, `after_email_verify`, `send_verification_email`, `send_password_reset_email`, `after_oauth_login`

## Configuration

Pass inline kwargs or a config object. All options read from env vars with `FULLAUTH_` prefix.

```python
fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    access_token_expire_minutes=60,
    api_prefix="/api/v2",
    login_field="username",
    password_hash_algorithm="bcrypt",
    blacklist_backend="redis",
    redis_url="redis://localhost:6379/0",
    rate_limit_enabled=True,
    trusted_proxy_headers=["X-Forwarded-For"],
)
```

See [Configuration docs](https://mdfarhankc.github.io/fastapi-fullauth/configuration/) for all options.

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
