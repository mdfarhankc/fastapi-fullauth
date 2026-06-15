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

A complete, async-native authentication and authorization system for **FastAPI** - production-ready and pluggable. JWT access/refresh tokens with rotation, Argon2 password hashing, email verification, OAuth2 social login, passkeys, session management, and role-based access control, all out of the box. Bring your own database with the SQLModel or SQLAlchemy adapter, and opt into only the features you need.

## Features

- **JWT access + refresh tokens** with configurable expiry
- **Refresh token rotation** with reuse detection; revokes entire session family on replay
- **Session management**: list active sessions (device, IP, last used), revoke one device, or sign out everywhere else
- **Password hashing** via Argon2id (default) or bcrypt, with transparent rehashing
- **Email verification** and **password reset** flows with event hooks
- **Passkey (WebAuthn)**: passwordless login with fingerprint, Face ID, security keys
- **OAuth2 social login**: Google and GitHub, with multi-redirect-URI support
- **Role-based access control**: `current_user`, `require_role()`, `require_permission()`
- **Rate limiting**: per-route auth limits + global middleware (memory or Redis)
- **CSRF protection** and **security headers** middleware
- **Bearer or cookie transport**: opt into HttpOnly cookies that carry both access and refresh tokens, out of JavaScript's reach; bearer is the default
- **Pluggable adapters**: SQLModel, SQLAlchemy, or [write your own](https://mdfarhankc.github.io/fastapi-fullauth/adapters/custom/) for any data store
- **Generic type parameters**: define your own schemas with full IDE support and type safety
- **Composable routers**: include only the route groups you need
- **Event hooks**: `after_register`, `after_login`, `send_verification_email`, etc.
- **Custom JWT claims**: embed app-specific data in tokens
- **Structured logging**: all auth events, security violations, and failures logged
- **Redis support**: token blacklist and rate limiter backends
- **Python 3.10 - 3.14** supported

## Installation

The fastest way to start: one adapter plus every optional feature in a single extra.

```bash
# Recommended: SQLModel adapter + Redis, OAuth, passkeys, bcrypt
pip install "fastapi-fullauth[sqlmodel-standard]"

# Same, on the SQLAlchemy adapter
pip install "fastapi-fullauth[sqlalchemy-standard]"
```

Or stay minimal and add only what you use:

```bash
# Core + one ORM adapter (pick one)
pip install "fastapi-fullauth[sqlmodel]"

# Mix and match any extras
pip install "fastapi-fullauth[sqlalchemy,oauth,redis]"
```

| Extra | Adds |
|-------|------|
| `sqlmodel` / `sqlalchemy` | ORM adapter + Alembic (pick one) |
| `redis` | Redis backends for token blacklist, lockout, rate limiting, passkey challenges |
| `oauth` | OAuth2 social login (Google, GitHub) |
| `passkey` | Passkey / WebAuthn support |
| `bcrypt` | bcrypt password hashing (Argon2id is the default and needs no extra) |
| `sqlmodel-standard` / `sqlalchemy-standard` | One adapter plus **all** of the above |

> Quotes around the package spec keep shells like zsh from globbing the `[extras]`.

## Quick start

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import Relationship

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class User(UserMixin, table=True):
    refresh_tokens: list[RefreshToken] = Relationship()


engine = create_async_engine("sqlite+aiosqlite:///./app.db")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

app = FastAPI()
fullauth = FullAuth(
    adapter=SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
    ),
    config=FullAuthConfig(SECRET_KEY="your-secret-key"),
)
fullauth.init_app(app)
```

That's it; all auth routes are registered under `/api/v1/auth/` automatically. Create the tables with Alembic (see the [migrations guide](https://mdfarhankc.github.io/fastapi-fullauth/migrations/)) or `SQLModel.metadata.create_all` for a quick local start.

> The SQLite quick-start needs an async driver: `pip install aiosqlite`.

Omit `config` in dev and a random secret key is generated (tokens won't survive restarts).

### Composable routers

Opt in to a subset of routers:

```python
fullauth.init_app(app, include_routers=["auth", "profile"])
```

`include_routers=None` (default) registers every available router. Or wire routers manually for full control:

```python
app = FastAPI()
fullauth.bind(app)  # required for dependencies to work

app.include_router(fullauth.auth_router, prefix="/api/v1/auth")
app.include_router(fullauth.profile_router, prefix="/api/v1/auth")
```

| Router | Routes |
|--------|--------|
| `auth_router` | register, login, logout, refresh |
| `profile_router` | me, verified-me, update profile, delete account, change password |
| `verify_router` | email verification, password reset |
| `admin_router` | assign/remove roles and permissions (superuser) |
| `oauth_router` | OAuth provider routes (only if configured) |
| `passkey_router` | Passkey register, authenticate, list, delete (only if enabled) |
| `sessions_router` | list active sessions, revoke one device, sign out others |

### Middleware

`init_app()` does not wire any middleware automatically. Import what you want and add it yourself:

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

### Token transport

By default, tokens are returned in the response body for `Authorization: Bearer` use. Opt into cookie transport to carry both the access and refresh tokens in separate **HttpOnly** cookies, out of JavaScript's reach:

```python
from fastapi_fullauth.backends import CookieBackend

fullauth = FullAuth(
    adapter=adapter,
    config=config,
    backends=[CookieBackend(config)],
)
```

`/refresh` and `/logout` then read the tokens from the cookies, so the browser never stores them. Wire `CSRFMiddleware` whenever you use cookie transport.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create a new user |
| `POST` | `/auth/login` | Authenticate, get tokens |
| `POST` | `/auth/logout` | Blacklist token |
| `POST` | `/auth/refresh` | Rotate token pair |
| `GET` | `/auth/sessions` | List active sessions |
| `DELETE` | `/auth/sessions/{family_id}` | Revoke one session |
| `POST` | `/auth/sessions/revoke-others` | Sign out other sessions |
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
| `POST` | `/auth/admin/assign-permission` | Assign permission to role (superuser) |
| `POST` | `/auth/admin/remove-permission` | Remove permission from role (superuser) |
| `GET` | `/auth/admin/role-permissions/{role_name}` | List role's permissions (superuser) |

With OAuth enabled, additional routes are registered under `/auth/oauth/`. All routes are prefixed with `/api/v1` by default.

## Custom user schemas

Combine each mixin with `table=True` (or your `DeclarativeBase` for the SQLAlchemy adapter), then pass everything to the adapter:

```python
from sqlmodel import Field, Relationship
from fastapi_fullauth import FullAuth, FullAuthConfig, UserSchema, CreateUserSchema
from fastapi_fullauth.adapters import SQLModelAdapter
from fastapi_fullauth.models.sqlmodel import (
    RefreshTokenMixin, RoleMixin, UserMixin, UserRoleMixin,
)


class RefreshToken(RefreshTokenMixin, table=True): pass
class Role(RoleMixin, table=True): pass
class UserRole(UserRoleMixin, table=True): pass


class User(UserMixin, table=True):
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)
    roles: list[Role] = Relationship(link_model=UserRole)
    refresh_tokens: list[RefreshToken] = Relationship()


class MyUserSchema(UserSchema):
    display_name: str = ""
    phone: str = ""


class MyCreateSchema(CreateUserSchema):
    display_name: str = ""


fullauth = FullAuth(
    adapter=SQLModelAdapter(
        session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        role_model=Role,
        user_role_model=UserRole,
        user_schema=MyUserSchema,
        create_user_schema=MyCreateSchema,
    ),
    config=FullAuthConfig(SECRET_KEY="..."),
)
```

Full IDE autocompletion and type checking on custom fields:

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, current_active_verified_user

CurrentUser = Annotated[MyUserSchema, Depends(current_user)]
VerifiedUser = Annotated[MyUserSchema, Depends(current_active_verified_user)]

@app.get("/profile")
async def profile(user: CurrentUser):
    return {"name": user.display_name}  # IDE knows this field exists
```

## Protected routes

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, current_active_verified_user, current_superuser, require_role

CurrentUser = Annotated[UserSchema, Depends(current_user)]
VerifiedUser = Annotated[UserSchema, Depends(current_active_verified_user)]
SuperUser = Annotated[UserSchema, Depends(current_superuser)]

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
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.oauth.google import GoogleOAuthProvider
from fastapi_fullauth.oauth.github import GitHubOAuthProvider

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="..."),
    providers=[
        GoogleOAuthProvider(
            client_id="your-google-client-id",
            client_secret="your-google-secret",
            redirect_uris=[
                "http://localhost:3000/auth/callback",
                "https://myapp.com/auth/callback",
            ],
        ),
        GitHubOAuthProvider(
            client_id="your-github-client-id",
            client_secret="your-github-secret",
            redirect_uris=["http://localhost:3000/auth/callback"],
        ),
    ],
)
```

Requires `httpx`: `pip install "fastapi-fullauth[oauth]"`

> **Security note**: the OAuth `state` token is signed and carries the PKCE
> challenge, but it is not bound to the browser session. For defense against
> login-CSRF, also bind `state` to the initiating browser (e.g. a short-lived
> cookie you set before redirecting and verify on callback).

## Event hooks

```python
async def welcome(user):
    await send_email(user.email, "Welcome!")

async def send_verify(email, token):
    await send_email(email, f"Verify: https://myapp.com/verify?token={token}")

fullauth.hooks.on("after_register", welcome)
fullauth.hooks.on("send_verification_email", send_verify)
```

Events: `after_register`, `after_login`, `after_logout`, `after_password_change`, `after_password_reset`, `after_email_verify`, `send_verification_email`, `send_password_reset_email`, `after_oauth_login`, `after_oauth_register`

## Configuration

Pass a `FullAuthConfig` object or set env vars with `FULLAUTH_` prefix.

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        ACCESS_TOKEN_EXPIRE_MINUTES=60,
        API_PREFIX="/api/v2",
        LOGIN_FIELD="username",
        PASSWORD_HASH_ALGORITHM="bcrypt",
        BLACKLIST_BACKEND="redis",
        REDIS_URL="redis://localhost:6379/0",
        AUTH_RATE_LIMIT_ENABLED=True,
        TRUSTED_PROXY_HEADERS=["X-Forwarded-For"],
    ),
)
```

See [Configuration docs](https://mdfarhankc.github.io/fastapi-fullauth/configuration/) for all options.

## AI-friendly docs

Using an AI coding assistant? Point it at our LLM-optimized docs:

- **[llms.txt](https://mdfarhankc.github.io/fastapi-fullauth/llms.txt)**: concise overview with links to all doc pages
- **[llms-full.txt](https://mdfarhankc.github.io/fastapi-fullauth/llms-full.txt)**: full documentation in a single file

Works with Claude, Cursor, Copilot, and any tool that accepts a docs URL.

## Development

```bash
git clone https://github.com/mdfarhankc/fastapi-fullauth.git
cd fastapi-fullauth
uv sync --dev --extra sqlalchemy --extra sqlmodel
uv run pytest tests/ -v

# run examples
uv run uvicorn examples.sqlmodel_app.main:app --reload
```

## License

MIT
