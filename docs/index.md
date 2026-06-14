<p align="center">
  <img src="https://img.icons8.com/fluency/96/shield.png" alt="FastAPI FullAuth" width="80" height="80">
</p>

<h1 align="center" style="margin-bottom: 0.2rem;">FastAPI FullAuth</h1>

<p align="center">
  <em>Production-grade, async-native authentication and authorization for FastAPI.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/v/fastapi-fullauth?color=009688&label=pypi" alt="PyPI"></a>
  <a href="https://pypi.org/project/fastapi-fullauth/"><img src="https://img.shields.io/pypi/pyversions/fastapi-fullauth?color=009688" alt="Python"></a>
  <a href="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml"><img src="https://github.com/mdfarhankc/fastapi-fullauth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-009688" alt="License"></a>
</p>

<div class="hero-buttons" markdown>
[Get started](getting-started.md){ .md-button .md-button--primary }
[Architecture](architecture.md){ .md-button }
[GitHub](https://github.com/mdfarhankc/fastapi-fullauth){ .md-button }
</div>

---

Add a complete authentication and authorization system to your **FastAPI** project. FastAPI FullAuth is async-native and pluggable: JWT tokens, refresh rotation, password hashing, email verification, OAuth2 social login, passkeys, and role-based access, all opt-in.

## Why FastAPI FullAuth

<div class="grid cards" markdown>

- **Async-native**

    Built for `async`/`await` end to end on SQLAlchemy or SQLModel, with no sync bridges.

- **Secure by default**

    Argon2id hashing, refresh-token rotation with reuse detection, and account lockout out of the box.

- **Pluggable, not prescriptive**

    Bring your own user schema, adapter, and backends. Include only the routers you need.

- **Fully typed**

    Generic over your user schema, ships `py.typed`, and checked under `mypy --strict`.

</div>

## Install

```bash
pip install fastapi-fullauth[sqlmodel]
```

[Getting Started](getting-started.md) covers the SQLAlchemy, OAuth, passkey, Redis, and bcrypt extras.

## Quick example

```python
from fastapi import FastAPI
from sqlmodel import Relationship

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class User(UserMixin, table=True):
    refresh_tokens: list[RefreshToken] = Relationship()


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

This registers the auth routes under `/api/v1/auth/` automatically. Omit `SECRET_KEY` in development and a random one is generated (tokens won't survive restarts).

## What you get

<div class="grid cards" markdown>

- **Authentication**

    Register, login, logout, JWT refresh rotation, email verification, and password reset.

- **Social and passwordless**

    [OAuth2](oauth.md) with Google and GitHub, plus [passkeys](passkeys.md) (WebAuthn) for biometric login.

- **Authorization**

    Role-based access with `current_user`, `require_role()`, and `require_permission()`.

- **Protection**

    [Rate limiting](security/rate-limiting.md), account lockout, CSRF, and [security headers](security/middleware.md).

</div>

The combined router mounts under `/api/v1/auth` by default. Admin, OAuth, and passkey routes register only when your adapter supports them; the full route list is in [Getting Started](getting-started.md).

## Learn more

<div class="grid cards" markdown>

- [**Getting Started**](getting-started.md)

    Step-by-step setup, from install to protected routes.

- [**Architecture**](architecture.md)

    How tokens, adapters, and protection subsystems fit together.

- [**Configuration**](configuration.md)

    Every option, with production `.env` examples.

- [**Customization**](customization.md)

    Every extension point: custom adapters, schemas, claims, hooks, and transport.

- [**Troubleshooting**](troubleshooting.md)

    Common errors mapped to fixes.

</div>

## AI-friendly docs

Point your AI coding assistant at the LLM-optimized docs:

- [llms.txt](llms.txt): concise overview with links to all doc pages
- [llms-full.txt](llms-full.txt): full documentation in a single file

## License

MIT
