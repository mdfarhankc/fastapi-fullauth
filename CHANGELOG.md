# Changelog

## 0.6.0

### Breaking changes

- **Config-only API** — `FullAuth` no longer accepts `secret_key=`, `**config_kwargs`, or positional `config`. Pass `config=FullAuthConfig(SECRET_KEY="...")` or set `FULLAUTH_SECRET_KEY` env var. All params are keyword-only.
- **`enabled_routes` removed** — replaced by composable routers. Include only the routers you need instead of filtering route names.
- **`RouteName` type removed** — no longer needed with composable routers.
- **`configure_hasher()` removed** — hash algorithm is now passed explicitly from config through flows. No more global mutable state.
- **Schema auto-derivation removed** — `_derive_user_schema()` and `_resolve_create_schema()` deleted from all adapters and FullAuth. Define your own schemas extending `UserSchema` / `CreateUserSchema` and pass them to the adapter.
- **`create_user_schema` moved to adapter** — pass it to the adapter, not FullAuth: `InMemoryAdapter(user_schema=MyUser, create_user_schema=MyCreate)`.

### Added

- **Generic type parameters** — `AbstractUserAdapter[UserSchemaType, CreateUserSchemaType]`, `FullAuth[UserSchemaType, CreateUserSchemaType]` with PEP 696 defaults for full type safety
- **Composable routers** — `fullauth.auth_router`, `fullauth.profile_router`, `fullauth.verify_router`, `fullauth.admin_router`, `fullauth.oauth_router`. Each lazily created, include only what you need
- **Typed dependency factories** — `get_current_user_dependency(MyUser)`, `get_verified_user_dependency(MyUser)`, `get_superuser_dependency(MyUser)` for custom schema type safety
- `create_blacklist(config)` — extracted from FullAuth to `core/tokens.py`
- `create_rate_limiter(config, max, window)` — extracted from FullAuth to `protection/ratelimit.py`
- `UserSchemaType`, `CreateUserSchemaType` TypeVars exported from top-level package
- `UserSchema`, `CreateUserSchema` base classes exported from top-level package

### Changed

- **Router split** — 613-line monolithic `create_auth_router()` split into `create_auth_router()` (login/register/logout/refresh), `create_profile_router()` (me/update/delete/change-password), `create_verify_router()` (email verify/password reset), `create_admin_router()` (roles/permissions)
- **FullAuth slimmed** — factory methods extracted, composable router properties added, `_OAUTH_PROVIDER_REGISTRY` stays on class for now
- `fullauth.router` still works as before (composes all sub-routers), `fullauth.init_app(app)` unchanged
- `hash_password()` and `password_needs_rehash()` now accept explicit `algorithm` parameter (default `argon2id`)
- Shared request/response models extracted to `router/_models.py`
- RBAC permissions (`require_role`, `require_permission`) available via `fastapi_fullauth.dependencies` (removed `rbac/` re-export package will happen in next release)

### Removed

- `FullAuth._resolve_create_schema()` — auto-derivation of create schema from ORM model
- `SQLModelAdapter._derive_user_schema()` — auto-derivation of user schema
- `SQLAlchemyAdapter._derive_user_schema()` — auto-derivation of user schema
- `_SA_TYPE_MAP` and `_get_sa_type_map()` — SQLAlchemy type mapping for auto-derivation
- `FullAuth._create_blacklist()` — moved to `core/tokens.create_blacklist()`
- `FullAuth._create_rate_limiter()` — moved to `protection.ratelimit.create_rate_limiter()`
- `configure_hasher()` and `_algorithm` global from `core/crypto.py`

## 0.5.0

### Added

- **Structured logging** across all auth flows, security middleware, and OAuth — failed logins, account lockouts, token reuse, CSRF violations, rate limit hits, role changes, and account deletions are all logged via `logging.getLogger("fastapi_fullauth.*")`
- **Documentation site** — MkDocs with Material theme, auto-deployed to GitHub Pages via CI
- **Proxy-aware rate limiting** — new `TRUSTED_PROXY_HEADERS` config to read real client IPs from `X-Forwarded-For` and similar headers
- **SQLAlchemy example app** (`examples/sqlalchemy_app/`)
- **`update_user` field validation** — rejects unknown fields with 422 instead of passing them to the DB
- SQLModel adapter now accepts both SQLModel's and SQLAlchemy's `AsyncSession`
- `OAuthAccountRecord` exported from `fastapi_fullauth.adapters.sqlmodel`

### Fixed

- **OAuth state token TTL was ignored** — `OAUTH_STATE_EXPIRE_SECONDS` config had no effect; state tokens used `ACCESS_TOKEN_EXPIRE_MINUTES` (30 min) instead of the configured 5 min
- **Refresh token reuse detection race condition** — two concurrent `/refresh` requests could both succeed before either revoked the token; added explicit blacklist check before issuing new tokens
- **OAuth error messages leaked provider internals** — raw API responses from Google/GitHub were exposed in HTTP error details; now logged internally and replaced with generic messages

### Changed

- README rewritten with centered hero layout, badges, and documentation links
- Documentation URL updated in `pyproject.toml` to point to GitHub Pages

## 0.4.0

### Added

- **OAuth2 social login** — Google and GitHub out of the box, extensible for custom providers
  - `GET /oauth/{provider}/authorize` — get authorization URL
  - `POST /oauth/{provider}/callback` — exchange code for JWT tokens
  - `GET /oauth/providers` — list configured providers
  - `GET /oauth/accounts` — list linked OAuth accounts
  - `DELETE /oauth/accounts/{provider}` — unlink a provider (with lockout prevention)
- `OAuthProvider` abstract base class for implementing custom providers
- `OAuthAccount` and `OAuthUserInfo` types
- `OAuthAccountRecord` / `OAuthAccountModel` for SQLModel and SQLAlchemy adapters
- OAuth adapter methods on all adapters (memory, SQLModel, SQLAlchemy)
- `OAUTH_PROVIDERS`, `OAUTH_STATE_EXPIRE_SECONDS`, `OAUTH_AUTO_LINK_BY_EMAIL` config fields
- `after_oauth_login` hook event
- `oauth` optional dependency group (`pip install fastapi-fullauth[oauth]`)
- Auto-link OAuth to existing user by email (configurable)
- Auto-verify email when provider confirms it
- Lockout prevention — can't unlink last login method
- Multiple `redirect_uris` per OAuth provider — supports web, mobile, and production frontends from one config. Client passes `?redirect_uri=` on authorize, validated against allowed list.

## 0.3.0

### Breaking changes

- **`create_refresh_token` returns `RefreshTokenMeta`** — previously returned a plain `str`. Now returns a `NamedTuple` with `.token`, `.expires_at`, `.family_id`. Callers that used the raw string must access `.token`.
- **`create_token_pair` returns `tuple[str, RefreshTokenMeta]`** — second element is now `RefreshTokenMeta` instead of `str`.
- **`revoke_all_user_refresh_tokens` is now required** on custom adapters — new abstract method on `AbstractUserAdapter`.

### Added

- `current_superuser` dependency and `SuperUser` annotated type
- `CurrentUser`, `VerifiedUser`, `SuperUser` annotated types in `dependencies.current_user` for cleaner route signatures
- `RefreshTokenMeta` named tuple — avoids decoding freshly created tokens just to read `expires_at` and `family_id`
- `FullAuth.get_custom_claims(user)` — moved custom claims logic from router into the class, with validation against reserved JWT keys (`sub`, `exp`, `type`, etc.)
- `revoke_all_user_refresh_tokens(user_id)` on all adapters — bulk session revocation
- Session revocation on password reset, password change, and account deletion
- `configure_hasher()` — wires `PASSWORD_HASH_ALGORITHM` config to the actual hasher; supports `argon2id` and `bcrypt`
- Automatic password rehash on login when hash algorithm or params have changed
- Register now checks uniqueness on `login_field` (not just email) when `login_field != "email"`
- `InMemoryBlacklist` now respects `ttl_seconds` — expired entries are evicted on lookup
- `RateLimiter` evicts keys with empty timestamp lists to prevent unbounded dict growth
- `description` parameter on all route decorators for Swagger docs

### Fixed

- `current_active_verified_user` was missing `payload.type != "access"` check — refresh tokens could pass through
- Purpose tokens (password reset, email verify) could be used as regular access tokens — `current_user` now rejects tokens with `extra.purpose`
- Duplicate token decode + user lookup across dependencies, router endpoints, and admin routes — consolidated into reusable `current_user` dependency chain
- Duplicate `roles` + `extra_claims` fetch in refresh route — pulled above the if/else branch
- Login flow fetched the user from DB twice (once in router, once in `login()`) — now accepts pre-fetched user
- Unused `request: Request` parameters in dependencies and routes
- Removed duplicate docstrings on routes (kept `description=` on decorators)
- `require_permission` was a full copy of `require_role` — now delegates to it

### Internal

- Route order follows auth lifecycle: register → login → refresh → logout → user → email/password → admin
- `require_role` / `require_permission` use `Depends(current_user)` instead of duplicating token logic
- Removed `_get_custom_claims` module-level function from router

## 0.2.0

### Breaking changes

- **JSON login** — `POST /login` now accepts `{"email": "...", "password": "..."}` instead of form data. Swagger auth uses bearer token input instead of username/password form.
- **No default User model** — SQLModel and SQLAlchemy adapters no longer ship a concrete `User`/`UserModel` table class. Users must define their own model from `UserBase`. This eliminates relationship conflicts when subclassing.
- **`user_model` is required** — `SQLModelAdapter(session_maker, user_model=MyUser)` — no default.
- **Removed `min_length=8`** from `CreateUserSchema` — password length is now fully controlled by `PasswordValidator` and `PASSWORD_MIN_LENGTH` config.
- **`SQLAlchemyAdapter` renamed `UserModel` to `UserBase`** — import `UserBase` instead.

### Added

- `POST /auth/change-password` — verifies current password, validates new
- `PATCH /auth/me` — update profile with protected field filtering
- `DELETE /auth/me` — self-deletion
- `expires_in` in login/refresh responses
- Per-IP auth rate limiting on login, register, password-reset (`AUTH_RATE_LIMIT_*` config)
- `LOGIN_FIELD` config — login by email, username, phone, or any model field
- `get_user_by_field()` on all adapters for generic field lookups
- Structured example apps (`examples/memory_app/`, `examples/sqlmodel_app/`)

### Fixed

- `InMemoryAdapter.update_user` returning base `UserSchema` instead of custom schema
- Stale `User.id` / `UserModel` references in adapter queries after model removal
- Parameter ordering in adapter constructors (required params before optional)

## 0.1.0

Initial release.

- JWT access/refresh tokens with rotation and blacklisting
- Argon2id password hashing
- Auth flows: register, login, logout, password reset, email verification
- Brute-force lockout, per-IP rate limiting, CSRF, security headers
- Bearer and cookie backends
- SQLAlchemy, SQLModel, and InMemory adapters
- Redis blacklist backend
- Refresh token persistence with family tracking and reuse detection
- Flat config (`secret_key=...`) or full `FullAuthConfig` object
- Auto-derive schemas from ORM model fields
- Auto-wire middleware from config flags
- Route enum, event hooks, email hooks
- `current_user`, `current_active_verified_user`, `require_role` dependencies
- 97 tests
