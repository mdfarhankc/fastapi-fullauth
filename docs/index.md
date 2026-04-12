# FastAPI FullAuth

<div class="fullauth-title">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="64" height="64" fill="#009688">
    <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/>
  </svg>
  <span class="fullauth-title__text"><span class="accent">FastAPI</span>FullAuth</span>
</div>

<p class="fullauth-tagline"><em>Ready-to-use, async-native authentication and authorization for FastAPI.</em></p>

<div class="fullauth-badges">
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/v/fastapi-fullauth?color=009688&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/pyversions/fastapi-fullauth?color=009688" alt="Python"></a>
  <a href="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml"><img src="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-009688" alt="License"></a>
</div>

<div class="fullauth-links" markdown>

**Documentation**: [https://mdfarhankc.github.io/fastapi-fullauth](https://mdfarhankc.github.io/fastapi-fullauth)

**Source Code**: [https://github.com/mdfarhankc/fastapi-fullauth](https://github.com/mdfarhankc/fastapi-fullauth)

</div>

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
- **Auto-derived schemas** — custom user fields are picked up automatically
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
from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.memory import InMemoryAdapter

app = FastAPI()

fullauth = FullAuth(
    secret_key="your-secret-key",
    adapter=InMemoryAdapter(),
)
fullauth.init_app(app)
```

This gives you `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/me`, `/auth/change-password`, `/auth/password-reset/*`, `/auth/verify-email/*`, and admin role management — all under `/api/v1` by default.

Omit `secret_key` in dev and a random one is generated (tokens won't survive restarts).

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

## License

MIT
