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
- **Refresh token rotation** with reuse detection (revokes entire session family on replay)
- **Password hashing** via Argon2id (default) or bcrypt
- **Email verification** and **password reset** flows with event hooks
- **OAuth2 social login** — Google and GitHub, with multi-redirect-URI support
- **Role-based access control** — `CurrentUser`, `VerifiedUser`, `SuperUser`, `require_role()`
- **Rate limiting** — per-route auth limits + global middleware (memory or Redis)
- **CSRF protection** and **security headers** middleware
- **Pluggable adapters** — SQLModel, SQLAlchemy, or in-memory
- **Generic type parameters** — define your own schemas with full IDE support and type safety
- **Composable routers** — include only the route groups you need
- **Event hooks** — `after_register`, `after_login`, `send_verification_email`, etc.
- **Custom JWT claims** — embed app-specific data in tokens
- **Redis support** — token blacklist and rate limiter backends
- **Python 3.10 -- 3.14** supported

## Installation

```bash
pip install fastapi-fullauth

# with an ORM adapter
pip install fastapi-fullauth[sqlmodel]
pip install fastapi-fullauth[sqlalchemy]

# with redis for token blacklisting
pip install fastapi-fullauth[sqlmodel,redis]

# with OAuth2 social login
pip install fastapi-fullauth[sqlmodel,oauth]

# everything
pip install fastapi-fullauth[all]
```

## Example

```python
from fastapi import FastAPI
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter

app = FastAPI()

fullauth = FullAuth(
    adapter=InMemoryAdapter(),
    config=FullAuthConfig(
        SECRET_KEY="your-secret-key",
    ),
)
fullauth.init_app(app)
```

This registers all auth routes under `/api/v1/auth/` automatically.

Omit `SECRET_KEY` in dev and a random one is generated (tokens won't survive restarts).

### Composable routers

Include only the route groups you need:

```python
app = FastAPI()
app.state.fullauth = fullauth

app.include_router(fullauth.auth_router, prefix="/api/v1/auth")
app.include_router(fullauth.profile_router, prefix="/api/v1/auth")
# skip verify, admin, oauth
```

| Router | Routes |
|--------|--------|
| `auth_router` | register, login, logout, refresh |
| `profile_router` | me, verified-me, update profile, delete account, change password |
| `verify_router` | email verification, password reset |
| `admin_router` | assign/remove roles and permissions (superuser) |
| `oauth_router` | OAuth provider routes (only if configured) |

`fullauth.init_app(app)` includes all of them.

## Routes

<div class="fullauth-routes" markdown>

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
| `POST` | `/auth/admin/assign-permission` | Assign permission to role (superuser) |
| `POST` | `/auth/admin/remove-permission` | Remove permission from role (superuser) |
| `GET` | `/auth/admin/role-permissions/{role}` | List role's permissions (superuser) |

</div>

With OAuth enabled, additional routes are registered under `/auth/oauth/`. See [OAuth2 Social Login](oauth.md).

All routes are prefixed with `/api/v1` by default (configurable via `API_PREFIX`).

## AI-friendly docs

Using an AI coding assistant? Point it at our LLM-optimized docs:

- **[llms.txt](llms.txt)** — concise overview with links to all doc pages
- **[llms-full.txt](llms-full.txt)** — full documentation in a single file

Works with Claude, Cursor, Copilot, and any tool that accepts a docs URL.

## License

MIT
