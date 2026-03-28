# Changelog

## 0.1.0 (2026-03-28)

### Added

- **Core auth engine**: JWT access/refresh tokens with rotation and in-memory blacklisting
- **Password hashing**: Argon2id by default via argon2-cffi
- **Auth flows**: register, login, logout, password reset, email verification
- **Brute-force protection**: progressive lockout after configurable failed attempts
- **Auth backends**: Bearer token and HttpOnly cookie backends (pluggable)
- **FastAPI dependencies**: `current_user`, `current_active_verified_user`, `require_role`, `require_permission`
- **Pre-built router**: `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/password-reset/*`, `/auth/verify-email/*`
- **Configuration**: `FullAuthConfig` via pydantic-settings with `FULLAUTH_` env var prefix
- **ORM adapters**: SQLAlchemy (async), SQLModel (async), and InMemory (for testing)
- **Pluggable email verification**: `on_send_verification_email` callback
- **Modular extras**: `[sqlalchemy]`, `[sqlmodel]` — install only what you need
- **Alembic migration helpers**: `include_fullauth_models()` and `get_fullauth_metadata()` for autogenerate support
- **GitHub Actions CI**: lint + test matrix across Python 3.10–3.13
- **Test suite**: 35 tests covering crypto, tokens, lockout, all auth flows, and email verification
- **Examples**: basic, SQLAlchemy, SQLModel, and email verification apps
