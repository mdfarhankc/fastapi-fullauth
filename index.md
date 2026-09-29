# FastAPI FullAuth

*Production-grade, async-native authentication and authorization for FastAPI.*

[Get started](https://mdfarhankc.github.io/fastapi-fullauth/getting-started/index.md) [Architecture](https://mdfarhankc.github.io/fastapi-fullauth/architecture/index.md) [GitHub](https://github.com/mdfarhankc/fastapi-fullauth)

______________________________________________________________________

Add a complete authentication and authorization system to your **FastAPI** project. FastAPI FullAuth is async-native and pluggable: JWT tokens, refresh rotation, password hashing, email verification, OAuth2 social login, passkeys, and role-based access, all opt-in.

## Why FastAPI FullAuth

- **Async-native**

  Built for `async`/`await` end to end on SQLAlchemy or SQLModel, with no sync bridges.

- **Secure by default**

  Argon2id hashing, refresh-token rotation with reuse detection, refresh tokens stored as sha256 digests, account lockout, and anti-enumeration and timing-attack defenses - all on out of the box.

- **Pluggable, not prescriptive**

  Bring your own user schema, adapter, and backends. Include only the routers you need.

- **Fully typed**

  Generic over your user schema, ships `py.typed`, and checked under `mypy --strict`.

## Install

```
pip install fastapi-fullauth[sqlmodel]
```

[Getting Started](https://mdfarhankc.github.io/fastapi-fullauth/getting-started/index.md) covers the SQLAlchemy, OAuth, passkey, Redis, and bcrypt extras.

## Quick example

```
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


engine = create_async_engine("sqlite+aiosqlite:///app.db")
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

This registers the auth routes under `/api/v1/auth/` automatically. Omit `SECRET_KEY` in development and a random one is generated (tokens won't survive restarts).

## What you get

- **Authentication**

  Register, login, logout, JWT refresh rotation, email verification, and password reset.

- **Social and passwordless**

  [OAuth2](https://mdfarhankc.github.io/fastapi-fullauth/oauth/index.md) with Google, GitHub, Discord, and GitLab, plus [passkeys](https://mdfarhankc.github.io/fastapi-fullauth/passkeys/index.md) (WebAuthn) for biometric login.

- **Authorization**

  Role-based access with `current_user`, `require_role()`, and `require_permission()`.

- **Protection**

  [Rate limiting](https://mdfarhankc.github.io/fastapi-fullauth/security/rate-limiting/index.md), account lockout, CSRF, and [security headers](https://mdfarhankc.github.io/fastapi-fullauth/security/middleware/index.md).

The combined router mounts under `/api/v1/auth` by default. Admin, OAuth, and passkey routes register only when your adapter supports them; the full route list is in [Getting Started](https://mdfarhankc.github.io/fastapi-fullauth/getting-started/index.md).

## Learn more

- [**Getting Started**](https://mdfarhankc.github.io/fastapi-fullauth/getting-started/index.md)

  Step-by-step setup, from install to protected routes.

- [**Architecture**](https://mdfarhankc.github.io/fastapi-fullauth/architecture/index.md)

  How tokens, adapters, and protection subsystems fit together.

- [**Configuration**](https://mdfarhankc.github.io/fastapi-fullauth/configuration/index.md)

  Every option, with production `.env` examples.

- [**Customization**](https://mdfarhankc.github.io/fastapi-fullauth/customization/index.md)

  Every extension point: custom adapters, schemas, claims, hooks, and transport.

- [**Troubleshooting**](https://mdfarhankc.github.io/fastapi-fullauth/troubleshooting/index.md)

  Common errors mapped to fixes.

## AI-friendly docs

Install the fastapi-fullauth [Agent Skill](https://agentskills.io/) so your coding agent (Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and others) knows the library's APIs, contracts, and pitfalls:

```
npx skills add mdfarhankc/fastapi-fullauth
```

For tools that take a docs URL instead:

- [llms.txt](https://mdfarhankc.github.io/fastapi-fullauth/llms.txt): concise overview with links to all doc pages
- [llms-full.txt](https://mdfarhankc.github.io/fastapi-fullauth/llms-full.txt): full documentation in a single file

## License

MIT
