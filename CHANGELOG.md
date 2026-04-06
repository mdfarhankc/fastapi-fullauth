# Changelog

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
