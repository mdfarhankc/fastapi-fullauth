# Changelog

## 0.1.0 (unreleased)

### Added

- **Core auth engine**: JWT access/refresh tokens with rotation and blacklisting
- **Password hashing**: Argon2id by default via argon2-cffi
- **Auth flows**: register, login, logout, password reset, email verification
- **Brute-force protection**: progressive lockout after configurable failed attempts
- **Auth backends**: Bearer token and HttpOnly cookie backends (pluggable)
- **FastAPI dependencies**: `current_user`, `current_active_verified_user`, `require_role`, `require_permission`, `CurrentUser`, `VerifiedUser`
- **Pre-built router**: `/auth/me` (GET/PATCH/DELETE), `/auth/me/verified`, `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/change-password`, `/auth/password-reset/*`, `/auth/verify-email/*`, `/auth/admin/*`
- **Change password**: `POST /auth/change-password` — verifies current password, validates new password strength
- **Update profile**: `PATCH /auth/me` — update user fields with protected field filtering
- **Delete account**: `DELETE /auth/me` — self-deletion for logged-in users
- **Token expires_in**: login and refresh responses include `expires_in` (seconds) for frontend token refresh scheduling
- **Auth route rate limiting**: per-IP rate limits on login, register, and password-reset routes (configurable via `AUTH_RATE_LIMIT_*`)
- **Flat config**: `FullAuth(secret_key=..., adapter=...)` — no `FullAuthConfig` wrapper needed
- **Auto SECRET_KEY**: omit `secret_key` in dev mode, auto-generates with a warning
- **Route enum**: `Route.LOGIN`, `Route.ME`, etc. for type-safe `enabled_routes`
- **Auto-derive schemas**: `UserSchema` and `CreateUserSchema` auto-generated from ORM model fields
- **Auto-wire middleware**: SecurityHeaders, CSRF, and RateLimit auto-added by `init_app()` from config flags
- **Email hooks**: `send_verification_email` and `send_password_reset_email` in the hooks system
- **Event hooks**: `after_register`, `after_login`, `after_logout`, `after_password_reset`, `after_email_verify`
- **Redis blacklist**: async `RedisBlacklist` backend via `redis.asyncio` — activate with `BLACKLIST_BACKEND="redis"`
- **Refresh token persistence**: stored in DB with family tracking for theft detection
- **Token reuse detection**: replaying a used refresh token revokes the entire token family
- **Logout refresh revocation**: pass `refresh_token` in logout body to revoke the session family
- **Configuration**: `FullAuthConfig` via pydantic-settings with `FULLAUTH_` env var prefix, or inline kwargs
- **ORM adapters**: SQLAlchemy (async), SQLModel (async), and InMemory (for testing)
- **Modular extras**: `[sqlalchemy]`, `[sqlmodel]`, `[redis]` — install only what you need
- **Alembic migration helpers**: `include_fullauth_models()` and `get_fullauth_metadata()`
- **Password validation**: configurable rules (length, uppercase, digit, special, blocked list)
- **Custom token claims**: `on_create_token_claims` callback embedded in JWTs
- **Utilities**: `create_superuser()`, `generate_secret_key()`
- **Test suite**: 97 tests covering all auth flows, tokens, middleware, DX, refresh token security, and new endpoints
- **Examples**: InMemory, SQLAlchemy, and SQLModel demo apps
