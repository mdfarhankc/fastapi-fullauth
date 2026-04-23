# Changelog

## 0.9.0

### Breaking changes

- **Lockout now returns `401`** instead of `423 Locked`. Clients that branched on `423` to render a "your account is locked" UI will silently fall into the generic credentials-error path. The change is deliberate — see Security below.
- **Email lookup is now case-insensitive.** On case-sensitive database collations (MySQL default, SQL Server), rows registered with mixed-case emails (`Alice@X.com`) will stop matching logins submitted in a different case. Run a one-off `UPDATE fullauth_users SET email = LOWER(TRIM(email))` before upgrading. PostgreSQL/SQLite with default collations are unaffected.

### Security

- Emails are now normalised (stripped + lowercased) on create, update, and lookup in both built-in adapters. Previously `Alice@X.com` and `alice@X.com` could register as separate accounts on case-sensitive collations (MySQL default, SQL Server).
- Login now returns the same generic `401 Could not validate credentials` response for a locked account as for a wrong password. Previously a `423 Locked` status let an attacker distinguish "email exists and is locked out" from "wrong password" — an enumeration signal once they'd exhausted the lockout counter on a target email. The `AccountLockedError` message no longer includes the identifier (cleaner logs too).
- Opt-in `PREVENT_REGISTRATION_ENUMERATION` setting (default `False`). When `True`, `/register` always responds `202` + `{"detail": "If this email isn't already registered, a verification email has been sent."}` whether the email was taken or not — attackers can't probe the user table through the registration endpoint. Off by default to keep the `201` + user / `409` conflict shape that most client apps expect.

### Fixed

- `BearerBackend` accepts any case of the `Bearer` auth scheme (`Bearer`, `bearer`, `BEARER`, mixed) per RFC 7235. Clients that sent a lowercase scheme were previously rejected with a 401.
- `require_role` tolerates a `UserSchema` subclass with no `roles` field — returns a clean `403` instead of `AttributeError` / `500`. The default schema doesn't ship with `roles`; apps using RBAC still need to add it to their custom schema.
- `hash_password(..., algorithm="bcrypt")` rejects passwords over 72 UTF-8 bytes with `InvalidPasswordError` instead of silently truncating. bcrypt's built-in truncation would otherwise cause subtle lockouts if an app later migrated to argon2id.
- SQLModel `UserBase.hashed_password` column is now `Text`. Argon2id hashes are ~97 characters; MySQL / MSSQL default `VARCHAR(255)` was still fine but the column type is explicit now, matching the SQLAlchemy adapter.
- `FullAuthConfig` validates passkey settings at construction time when `PASSKEY_ENABLED=True` — empty `PASSKEY_RP_ID` / `PASSKEY_ORIGINS`, RP ID with scheme or path, origin without scheme, and Redis backend without `REDIS_URL` all raise at config creation instead of surfacing as 500s at first request.

## 0.8.0

### Security

- OAuth auto-link-by-email now requires `info.email_verified=True` from the provider when an account with that email already exists. Without this gate, any provider that returns an unverified email (e.g. GitHub secondary addresses) could be used to hijack an existing account by registering the provider with the victim's email.
- Cookie backend's `delete_token` now matches the same `secure`/`samesite`/`path`/`domain` attributes used on set. Browsers ignore (or reject, for `SameSite=None`) a deletion that doesn't match — logout previously left the cookie in place on some setups.
- Refresh-token revocation is now an atomic compare-and-swap (`UPDATE ... WHERE revoked=false`). Two concurrent refresh calls with the same token can no longer both succeed by racing the old stored-state check. `AbstractUserAdapter.revoke_refresh_token` now returns `bool` — custom adapters should honour the CAS semantics.
- `create_user` catches `IntegrityError` from duplicate-email races and raises `UserAlreadyExistsError`. The register flow's pre-check only guards the common case; concurrent signups used to surface as 500s.
- OAuth account table now has a composite unique constraint on `(provider, provider_user_id)`. Existing SQL users should autogenerate an Alembic migration to add it. `create_oauth_account` now returns the existing row on concurrent-insert collisions instead of erroring.
- Password-reset and email-verification tokens now use their own TTLs (`PASSWORD_RESET_EXPIRE_MINUTES`, default 15; `EMAIL_VERIFY_EXPIRE_MINUTES`, default 1440) instead of inheriting `ACCESS_TOKEN_EXPIRE_MINUTES`. A production tweak to access-token lifetime for mobile clients no longer silently extends the window in which a stolen password-reset email grants an account takeover.

### Breaking changes

- **Models split into packages** — `adapters/sqlmodel/models.py` and `adapters/sqlalchemy/models.py` are now `models/` directories with `base.py`, `role.py`, `permission.py`, `oauth.py`. Old import paths (`from fastapi_fullauth.adapters.sqlmodel.models import ...`) still work via `__init__.py` re-exports. New selective imports: `from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord`.
- **`roles` removed from default `UserSchema`** — apps that use roles should extend `UserSchema` with `roles: list[str] = Field(default_factory=list)`. Apps without roles are unaffected.
- **Admin router auto-skipped** when adapter doesn't implement `RoleAdapterMixin`. OAuth/passkey routers auto-skipped similarly.
- **`AbstractUserAdapter.revoke_refresh_token` now returns `bool`** — custom adapters need to return `True` only when the token actually transitioned from not-revoked to revoked (CAS semantics).

### Added

- **Composable models** — only imported model groups register tables. Apps that don't need roles/permissions/oauth skip those tables entirely.
- **Selective migration helper** — `include_fullauth_models("sqlmodel", include=["base", "role"])` imports only specified model groups for Alembic.
- **`exclude_routers` param on `init_app()`** — `fullauth.init_app(app, exclude_routers=["admin"])` to skip routers you don't need.
- **`bind(app)` method** — bind FullAuth to a FastAPI app for composable router usage. Called automatically by `init_app()` and `init_middleware()`.
- **`init_middleware()` method** — wire up middleware independently when using composable routers.
- **`RouterName` type** — `Literal["auth", "profile", "verify", "admin", "oauth"]` for type-safe router exclusion.
- **`AuthRateLimiter` class** — per-route auth rate limiting extracted from FullAuth into its own class.
- **`exchange_oauth_code()`, `link_or_create_user()`, `issue_oauth_tokens()`** — OAuth callback split into composable flow functions. `oauth_callback()` still works as before (delegates to the three).
- **`register_lockout_backend()`** — register custom lockout backends for `create_lockout()` factory.
- **`register_rate_limiter_backend()`** — register custom rate limiter backends for `create_rate_limiter()` factory.
- **Passkey (WebAuthn) authentication** — passwordless login with fingerprint, Face ID, security keys. Register, authenticate, list, and delete passkeys. Requires `pip install fastapi-fullauth[passkey]` and `PASSKEY_ENABLED=True`.
- **`ChallengeStore`** — abstract challenge store with InMemory and Redis backends for WebAuthn flows.
- **`PasskeyAdapterMixin`** — adapter mixin for passkey credential persistence.
- **Adapter mixins** — `AbstractUserAdapter` split into composable interfaces: `RoleAdapterMixin`, `PermissionAdapterMixin`, `OAuthAdapterMixin`, `PasskeyAdapterMixin`. Custom adapters implement only what they need. Built-in adapters inherit all mixins (backward compatible).

### Changed

- Adapter model imports are lazy — importing the adapter no longer registers role/permission/oauth tables
- Rate limiting extracted from FullAuth `__init__` into `AuthRateLimiter`
- SQLModelAdapter `session_maker` type hint accepts both session types cleanly
- `TokenClaimsBuilder` and `RouterName` moved to `types.py`
- `init_app()` and `init_middleware()` are now idempotent. Calling either twice on the same FastAPI app emits a `UserWarning` and is a no-op. Previously a second call (e.g. `init_app(app)` followed by a stray `init_middleware(app)`) doubled the middleware stack — duplicate security headers, two rate-limiter instances halving the effective limit, and a CSRF layer validating another CSRF layer's cookies.
- JWT decode now tolerates clock drift between services via `JWT_LEEWAY_SECONDS` (default 30). Eliminates sporadic 401s caused by ±30 s skew between client and server clocks or across load-balanced instances.
- `FullAuthConfig` reads `.env` in the current working directory by default (`env_file=".env"`), and ignores unknown `FULLAUTH_*` vars instead of erroring (`extra="ignore"`). Local dev "just works" without passing `_env_file=".env"` explicitly. Cloud deployments are unaffected — pydantic-settings' precedence is init kwargs → `os.environ` → `.env` → defaults, so platform-injected env vars always win, and a missing `.env` is a silent no-op. Use `FullAuthConfig(_env_file="…")` or a `SettingsConfigDict` subclass to read a different file.

## 0.7.0

### Breaking changes

- **InMemory adapter removed** — use SQLModel + SQLite for prototyping instead.
- **`UserID` is now `UUID`** (was `str | int | UUID`) — all adapter methods, `RefreshToken.user_id`, `OAuthAccount.user_id`, and `RoleAssignment.user_id` are now `UUID`.
- **OAuth providers passed as objects** — `FullAuth(providers=[GoogleOAuthProvider(...)])` replaces `OAUTH_PROVIDERS` dict in config. `OAuthProviderConfig` removed.
- **`OAuthProvider` simplified** — only `redirect_uris: list[str]` (removed singular `redirect_uri`). `get_redirect_uri()` removed.
- **`redirect_uri` required in authorize URL** — clients must pass `?redirect_uri=` in the OAuth authorize request.
- **`include_user_in_login` moved to config** — use `FullAuthConfig(INCLUDE_USER_IN_LOGIN=True)` or `FULLAUTH_INCLUDE_USER_IN_LOGIN=true` env var instead of `FullAuth(include_user_in_login=True)`.
- **Login response always includes `user` field** — when `INCLUDE_USER_IN_LOGIN=False`, `user` is `null` (previously the key was absent). When `True`, `user` contains the full user schema object.

### Added

- **Redis lockout backend** — `LOCKOUT_BACKEND="redis"` for multi-worker deployments
- `LOCKOUT_ENABLED` config — disable account lockout entirely (`False`)
- `INCLUDE_USER_IN_LOGIN` config — include user object in login/OAuth callback response
- `LoginResponse` dynamic model — login and OAuth callback routes now have proper `response_model` with typed `user` field matching the configured user schema
- `validate_profile_updates` flow — profile field filtering extracted from router to `flows/update_profile.py`
- `NoValidFieldsError`, `UnknownFieldsError` exceptions for profile update validation
- `change_password` flow — business logic extracted from profile router
- `PROTECTED_FIELDS` ClassVar on `UserSchema` — users can extend in subclasses
- Password validation moved to flows (`register`, `reset_password`, `change_password`)
- `Makefile` with `make check`, `make test`, `make lint`, `make format`, `make docs`, etc.

### Changed

- `LockoutManager` is now an abstract base class with async methods
- `InMemoryLockoutManager` replaces the old sync `LockoutManager`
- `migrations/` package flattened to single `migrations.py` module (import paths unchanged)
- 4 `type: ignore` comments fixed (replaced with `getattr`, assertions, `model_validate`)
- 204 routes (`delete_me`, `unlink_oauth_account`) no longer return unnecessary `Response` objects
- Logout route return type corrected to `Response`
- All tests migrated from InMemory to SQLModel + SQLite
- Tests regrouped: `test_auth`, `test_profile`, `test_config`, `test_hooks`, `test_security`, `test_rbac`
- `UUID(payload.sub)` conversion at token boundaries (dependencies, router, flows)
- Removed `isinstance` str-to-UUID guards from adapters
- Removed `str(user.id)` / `str(row.user_id)` conversions — UUID used directly

### Removed

- `InMemoryAdapter` and `examples/memory_app/`
- `OAuthProviderConfig` from config
- `OAUTH_PROVIDERS` from `FullAuthConfig`
- `FullAuth._build_oauth_providers()` and `_OAUTH_PROVIDER_REGISTRY`
- `OAuthProvider.get_redirect_uri()` method
- `rbac/` package (was empty, just re-exported from `dependencies`)

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
- RBAC permissions (`require_role`, `require_permission`) available via `fastapi_fullauth.dependencies`

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
