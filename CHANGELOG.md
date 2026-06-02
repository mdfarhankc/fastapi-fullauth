# Changelog

## 0.12.0

### Added

- **`adapter.transaction()`** on the SQLAlchemy and SQLModel adapters. Runs several adapter calls in one transaction that commits together when the block exits or rolls back entirely on error. Conflict-prone inserts (`create_user`, `create_oauth_account`) use SAVEPOINTs so a unique-constraint hit rolls back only that statement and leaves the surrounding transaction usable. Works as-is on PostgreSQL and MySQL; on SQLite, configure the engine with SQLAlchemy's BEGIN-emulation recipe for correct SAVEPOINT/rollback behavior.
- **Injectable response schemas.** `FullAuth(..., login_response_schema=..., message_response_schema=...)` accept custom `LoginResponse`/`MessageResponse` subclasses (add optional fields to extend the token or message bodies). `LoginResponse`, `MessageResponse`, and `TokenPair` are now exported from the top-level package.
- **`FullAuth.enforce_rate_limit(request, route_name)`** resolves the client IP and applies the auth rate limit in one call.
- **PKCE for OAuth (RFC 7636).** The authorization-code flow now sends an S256 `code_challenge` on authorize and the matching `code_verifier` on token exchange for providers that support it (Google and GitHub). The verifier is derived from the signed state token's nonce, so the flow stays stateless and the verifier never travels through the browser. Enabled by default via `OAUTH_PKCE_ENABLED`; custom providers opt in with `supports_pkce = True`.
- **Resource cleanup via `FullAuth.aclose()`.** Closes pooled resources: Redis connections (blacklist, lockout, rate limiter, challenge store) and OAuth HTTP clients. `init_app()` registers it on app shutdown automatically; call it yourself if you pass a custom `lifespan` to FastAPI. OAuth providers now reuse a single pooled `httpx.AsyncClient` across requests instead of opening one per call.

### Changed

- **Typed profile-update body.** `PATCH /me` now uses a model generated from the user schema's non-protected fields, so the updatable fields appear in the OpenAPI schema instead of a free-form object. Request handling is unchanged: protected fields are ignored and unknown fields still return 422.
- Internal: the SQLAlchemy and SQLModel adapters now share a single implementation (`_BaseSQLAlchemyAdapter`). Public adapter classes, signatures, and type hints are unchanged.
- Internal: login, OAuth, passkey, and refresh-token rotation now share an `issue_token_pair` helper, and the per-route rate-limit plus client-IP boilerplate is centralized on `FullAuth.enforce_rate_limit`.

## 0.11.0

### Breaking changes

- **`CurrentUser`, `VerifiedUser`, `SuperUser` removed from public API.** Build your own typed dependencies with `Annotated[YourSchema, Depends(current_user)]`.
- **Factory functions removed.** `get_current_user_dependency()`, `get_verified_user_dependency()`, `get_superuser_dependency()` are gone. Use `current_user`, `current_active_verified_user`, `current_superuser` directly with `Depends()`.

### Added

- **`get_fullauth` exported** from `fastapi_fullauth.dependencies`. Gives custom dependencies access to the full `FullAuth` instance (adapter, token engine, config, hooks, etc.).
- **Architecture docs** - explains how the library works internally (token lifecycle, adapters, protection subsystems).
- **Passkeys docs** - complete WebAuthn guide with setup, registration/authentication flows, frontend integration, clone detection.
- **Frontend integration guide** - framework-agnostic walkthrough of OAuth, passkey, email verification, and password reset flows.
- **Testing guide** - how to test apps built with fastapi-fullauth.
- **Troubleshooting guide** - common errors and solutions.
- All existing doc pages expanded with explanations, examples, and missing content.

## 0.10.0

### Breaking changes

- **`hashed_password` is nullable** on `UserMixin` (both SQLAlchemy and SQLModel). OAuth-only users are inserted with `hashed_password=NULL` instead of a fake random hash. The previous `has_usable_password` boolean is gone; `hashed_password IS NOT NULL` is now the single signal.
- **`/auth/set-password` route removed.** First-time password creation for OAuth-only users now goes through `/auth/change-password` with `current_password` omitted = the route accepts the missing field only when the stored hash is `NULL`. Users with an existing password must still supply it. The previous `set_password` flow checked `getattr(user, "has_usable_password", True)` against a `UserSchema` that didn't include the field, so OAuth-only users on the default schema could never call it successfully; this is now closed.
- **`flows.set_password` module removed.** Folded into `flows.change_password`, whose `current_password` parameter is now `str | None = None`.
- **`AbstractUserAdapter.create_user` signature change.** `hashed_password: str` is now `hashed_password: str | None`. Custom adapters must accept `None` and persist it. Built-in adapters already do.
- **`flows.oauth.link_or_create_user` and `flows.oauth.oauth_callback` no longer take `hash_algorithm`.** OAuth users have no password to hash anymore.
- **`ChangePasswordRequest.current_password` is now `str | None`.** Clients that always sent it keep working; clients can omit it when the user has no stored password.
- **`ChallengeStore` moved from `core.challenges` to `protection.challenges`.** Import path change: `from fastapi_fullauth.protection.challenges import ChallengeStore, InMemoryChallengeStore, RedisChallengeStore, create_challenge_store, register_challenge_store_backend`. Also exported from the `fastapi_fullauth.protection` package. The challenge store is a stateful anti-replay defence for WebAuthn = it belongs with the other defensive stores (`lockout`, `ratelimit`) rather than next to `TokenEngine` in `core/`.

- **Built-in models are now mixins.** The concrete `*Model` / `*Record` classes and the `FullAuthBase` declarative base are gone. Bring your own `DeclarativeBase` (SQLAlchemy) or `SQLModel` and combine each `*Mixin` to define the tables. The previous "must subclass `FullAuthBase`" rule forced every project to put its own tables on the library's metadata; mixins let you reuse one `Base` across `fastapi-fullauth` and the rest of the app.

  Before:

  ```python
  from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase, UserBase
  from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

  class User(UserBase, FullAuthBase):
      __tablename__ = "fullauth_users"
      roles: Mapped[list[RoleModel]] = relationship(secondary="fullauth_user_roles")
  ```

  After:

  ```python
  from sqlalchemy.orm import DeclarativeBase, Mapped, relationship
  from fastapi_fullauth.models.sqlalchemy import (
      UserMixin, RefreshTokenMixin, RoleMixin, UserRoleMixin,
  )

  class Base(DeclarativeBase):
      pass

  class RefreshToken(RefreshTokenMixin, Base): pass
  class Role(RoleMixin, Base): pass
  class UserRole(UserRoleMixin, Base): pass

  class User(UserMixin, Base):
      roles: Mapped[list[Role]] = relationship(
          secondary="fullauth_user_roles", lazy="selectin"
      )
      refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")
  ```

- **Model package moved to `fastapi_fullauth.models.{sqlalchemy,sqlmodel}`.** Old path `fastapi_fullauth.adapters.{sqlalchemy,sqlmodel}.models` is gone. Class names also normalised to `*Mixin`:
  - `UserBase` → `UserMixin`
  - `RefreshTokenModel` / `RefreshTokenRecord` → `RefreshTokenMixin`
  - `RoleModel` / `Role` → `RoleMixin`
  - `UserRoleModel` / `UserRoleLink` → `UserRoleMixin`
  - `PermissionModel` / `Permission` → `PermissionMixin`
  - `RolePermissionModel` / `RolePermissionLink` → `RolePermissionMixin`
  - `OAuthAccountModel` / `OAuthAccountRecord` → `OAuthAccountMixin`
  - `PasskeyModel` / `PasskeyRecord` → `PasskeyMixin`
  - `FullAuthBase` = removed

- **Adapter constructors take every concrete model as a keyword argument.** Required: `user_model`, `refresh_token_model`. Optional: `role_model`, `user_role_model`, `permission_model`, `role_permission_model`, `oauth_account_model`, `passkey_model` = pass only the ones for features you use. Calling a feature method without its model raises `RuntimeError`.

  ```python
  adapter = SQLAlchemyAdapter(
      session_maker=session_maker,
      user_model=User,
      refresh_token_model=RefreshToken,
      role_model=Role,
      user_role_model=UserRole,
      permission_model=Permission,
      role_permission_model=RolePermission,
      oauth_account_model=OAuthAccount,
  )
  ```

- **`fastapi_fullauth.migrations` module removed.** `include_fullauth_models()` and `get_fullauth_metadata()` are gone. The library no longer owns a metadata registry = your own `Base.metadata` is the source of truth. In `alembic/env.py`, `import app.models` to register the tables and set `target_metadata = Base.metadata`.

- **`INCLUDE_USER_IN_LOGIN` config removed.** Login, OAuth callback, and passkey-authenticate responses now always include the `user` field. The toggle existed only to preserve a pre-0.7 response shape; clients that key off `user is null` should switch to reading the field unconditionally.

- **`ACCOUNT_LOCKED_EXCEPTION` removed from `fastapi_fullauth.exceptions`.** Locked accounts have returned `401` (not `423`) since 0.9.0 to prevent enumeration via status code = the unused 423 helper is now gone too.

- **`ALGORITHM` constrained to `Literal["HS256", "HS384", "HS512"]`.** Free-form strings are rejected at config construction. Asymmetric algorithms (RS*/ES*) aren't supported yet = open an issue if you need them.

- **`SECRET_KEY` must be at least 32 characters** when explicitly set. Short keys are rejected at config construction. Auto-generated dev keys already exceed this.

- **Middleware is no longer auto-wired.** `init_app()` only mounts routers now = `CSRFMiddleware`, `SecurityHeadersMiddleware`, and `RateLimitMiddleware` are imported from `fastapi_fullauth.middleware` and added with `app.add_middleware(...)` like any other FastAPI middleware. Dropped: the `auto_middleware` kwarg on `init_app()`, the public `init_middleware()` method, and the `CSRF_ENABLED` / `INJECT_SECURITY_HEADERS` / `RATE_LIMIT_ENABLED` config flags. `create_rate_limiter()` is now exported from `fastapi_fullauth.protection` for users who want Redis-backed global limits.

- **`exclude_routers` renamed to `include_routers` on `init_app()`.** Allowlist instead of denylist. `include_routers=None` (default) registers every available router = same behaviour as before with no kwarg. Pass an explicit list (e.g. `["auth", "profile"]`) to opt in selectively.

### Migration guide (0.9.x → 0.10.0)

No data migration is required = table names and column shapes are unchanged.

1. Replace `fastapi_fullauth.adapters.{sqlalchemy,sqlmodel}.models.*` imports with `fastapi_fullauth.models.{sqlalchemy,sqlmodel}.*` and rename to the `*Mixin` classes.
2. Declare your project's `Base` (or use the existing one).
3. Define a concrete class per feature group you use (`RefreshToken`, `Role`, `UserRole`, etc.).
4. Pass all of them to the adapter via keyword args.
5. Drop `include_fullauth_models(...)` and `get_fullauth_metadata(...)` from `alembic/env.py`. Import `app.models`, then `target_metadata = Base.metadata`.

### Security

- **`/auth/refresh` now requires the refresh-token row to exist** before issuing a new token pair. Previously, a JWT that decoded cleanly (valid signature, unexpired) was enough = even if the corresponding row had been pruned or never existed. This affected both rotation and non-rotation paths.
- **Login timing oracle hardening (opt-in).** New `PREVENT_LOGIN_TIMING_ATTACKS: bool = False` config. When True, `/auth/login` runs a dummy argon2 verify on the unknown-user and missing-password paths, so response time no longer leaks whether the email exists. Off by default because it adds ~argon2 time to every failed lookup; flip it on when enumeration via timing is in your threat model.
- **CSRF middleware no longer pulls config from env at instantiation.** `CSRFMiddleware(secret=...)` is now required and validated (≥ 32 chars). `_resolve_secret()` (which built a fresh `FullAuthConfig` to pull `CSRF_SECRET` / `SECRET_KEY` on demand = and auto-generated a random `SECRET_KEY` if neither was set) is gone. `FullAuthConfig` also gains a validator that fails at construction if `CSRF_ENABLED=True` and the effective secret is shorter than 32 chars.
- `/auth/refresh` is now rate-limited via `AUTH_RATE_LIMIT_REFRESH` (default 30 req/min per IP). Without this, an attacker holding a stolen refresh token could hammer the endpoint for fresh access tokens, or use the response shape as a token-validation oracle. The default sits well above legitimate usage (a single user typically refreshes a handful of times per session) but caps abuse.
- `/verify-email/request`, `/verify-email/confirm`, `/password-reset/confirm`, `/oauth/{provider}/callback`, and `/passkeys/authenticate/complete` are now rate-limited using the existing `password-reset`, `login`, and `passkey-authenticate` buckets respectively. The reset/verify confirm endpoints were previously unbounded once an attacker possessed (or forged) a token candidate; OAuth callback and passkey completion are login flows but weren't gated.
- **Passkey authenticate-begin no longer leaks email existence.** When a client passes `email`, `allowCredentials` is always a list (possibly empty) instead of being omitted for unknown emails. Without an email, the route still allows discoverable credentials. Previously, an attacker could enumerate accounts by comparing the response shape.
- **Malformed JWT `sub` no longer 500s.** Token decoding succeeded but `UUID(payload.sub)` raised `ValueError` on non-UUID values. Now caught at every call site (`current_user`, `/refresh`, `verify_email`, `reset_password`, `logout` hook) and treated as an invalid token (`401` / `TokenError`).
- **`verify_password` no longer crashes on a malformed stored hash.** A garbage value in `hashed_password` (corrupted row, migration bug) caused `InvalidHashError` (argon2) or `ValueError` (bcrypt). Both are now caught and treated as a credential mismatch.

### Fixed

- **Hooks are now isolated.** A raising hook is logged via `fastapi_fullauth.hooks` and the next hook still runs. Previously a single failing hook (e.g. an email-send raising on a transient SMTP error) aborted every subsequent hook and surfaced as a 500 to the client = even though the user had already been created / password reset / etc. Hooks fire after the primary side effect commits, so a notification failure should never undo the operation the response reports.
- **`SQLAlchemyAdapter` eager-loads `roles` regardless of relationship lazy setting.** Added a `_user_query()` helper mirroring the SQLModel adapter that calls `selectinload(user_model.roles)` when the model has a `roles` attribute. Used by `get_user_by_id`, `get_user_by_field` (and `get_user_by_email`), `update_user`, `create_user`, and `get_user_roles`. Previously these methods built a bare `select(user_model)` and relied on the app to declare `lazy="selectin"` on the relationship; if the app left it default (`select`), `_to_schema` triggered an async lazy-load outside the session and raised `MissingGreenlet`. Behaviour now matches the SQLModel adapter.
- **Passkey router preserves tracebacks for unexpected failures.** The broad `except Exception as e: logger.error("...: %s", e)` in `/passkeys/register/complete` and `/passkeys/authenticate/complete` dropped the stack trace, making webauthn library failures effectively undebuggable. Now uses `logger.exception(...)` so the traceback lands in the `fastapi_fullauth.routers.passkey` logger alongside the request log line.
- **SQLAlchemy `UserMixin.email` is now `String(320)`** to match the explicit length on `OAuthAccountMixin.provider_email` and the SQLModel mixin's `max_length=320`. Previously the unsized column produced MySQL/MSSQL default-length VARCHARs (255 / 256) that silently truncated long addresses = Postgres/SQLite were unaffected. The local-part can legally be up to 64 chars and the domain up to 255 (RFC 5321), so 320 is the right ceiling.
- `/auth/refresh` was passing `str(user.id)` to `RefreshToken(user_id=...)` which expects `UUID`. Pydantic v2 coerced silently so there was no runtime break, but the path now passes `user.id` directly = consistent with `flows/login.py` and clean under static type checking.
- `LoginResponse` is now a real subclass of `TokenPair` with `user: UserSchema | None = None` instead of a dynamically created model with no static type. The dynamic factory still narrows the `user` field to the configured user schema for OpenAPI, but `LoginResponse(...)` calls now type-check cleanly in mypy/pyright.
- `DELETE /oauth/accounts/{provider}` was calling `delete_oauth_account(provider, user.id)` = passing the local user UUID where the provider's `provider_user_id` (e.g. a Google subject ID) was expected. The query never matched, so unlinking silently no-op'd. Now resolves the OAuth account for the current user first and passes the right `provider_user_id`. Returns `404` if the user doesn't have an account on that provider.
- `FullAuth.get_custom_claims` annotated as `-> dict[str, Any]` instead of bare `dict`.
- Passkey and OAuth flows now pass `user.id` (UUID) to `RefreshToken(user_id=...)` instead of `str(user.id)`, matching the password login path.
- OAuth state without a stored `redirect_uri` now falls back to `provider.redirect_uris[0]` instead of passing `None` to `provider.exchange_code(...)`. Test mocks were unaffected; production callers always set it.

### Changed

- **Strict mypy is now clean** across the entire codebase. The 184 strict-mode errors that had been parked for a future typed-hardening release are gone = `uv run mypy --strict fastapi_fullauth` passes 0/0. Mostly mechanical: missing `dict` type args, missing parameter/return annotations, `hash_password(algorithm=...)` Literal at call sites, ASGI middleware app/call_next types. Mixin-method calls through `AbstractUserAdapter` are now narrowed via `cast()` to the appropriate `RoleAdapterMixin` / `PermissionAdapterMixin` / `OAuthAdapterMixin` at each call site. SQLAlchemy 2.0 / SQLModel column-comparison stub limitations (`where(self.user_model.id == user_id)` types as `bool` instead of `ColumnElement[bool]`) are scoped to the two adapter modules via a focused `[[tool.mypy.overrides]]` block = the rest of the codebase stays strict.
- CI now runs `mypy --strict` on every push and PR to keep the type surface clean.
- `Development Status` classifier bumped from `3 - Alpha` to `4 - Beta`. Reflects 189 tests passing, multi-version CI on Python 3.10-3.14, OIDC-based PyPI publishing, the security hardening trail through 0.7.0-0.9.1, and `py.typed` shipped. Reserved `5 - Production/Stable` for v1.0.
- Added `Operating System :: OS Independent` classifier (CI runs on Linux and Windows).
- All dependency floors bumped to current stable versions: `fastapi>=0.136`, `pydantic[email]>=2.13`, `pydantic-settings>=2.14`, `pyjwt>=2.12`, `argon2-cffi>=25.1`, plus extras (`sqlalchemy>=2.0.49`, `alembic>=1.18`, `sqlmodel>=0.0.38`, `redis>=7.4`, `httpx>=0.28`, `webauthn>=2.7`).
- Version is now read dynamically from `fastapi_fullauth/__init__.py` via `[tool.hatch.version]` so a bump only touches one file.
- `[tool.pytest.ini_options]` migrated to `[tool.pytest]` (pytest 9 supports the flat key).
- `pytest-cov` added to the dev dependency group so contributors can run `uv run pytest --cov=fastapi_fullauth` locally.
- **`AuthRateLimiter.check()` now sets `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers on its `429` responses.** The global `RateLimitMiddleware` already sets the `X-RateLimit-*` triplet; the per-route auth limiter (login, register, password-reset, refresh, passkey-authenticate buckets) used to raise a bare `429` so clients couldn't tell when to retry. Headers come from the same limiter instance's `reset_time(client_ip)`.
- `_b64_decode` helper in `flows/passkey.py` now computes padding as `(-len(data)) % 4` instead of `4 - len(data) % 4`. Mathematically equivalent except when the input length is already a multiple of 4 = the old form appended `====` (four bytes) instead of nothing. `urlsafe_b64decode` is lenient enough to tolerate either, but the new form is the standard idiom.

## 0.9.1

### Added

- `py.typed` marker (PEP 561) ships with the package. Type annotations = including the generic `FullAuth[UserSchema, CreateUserSchema]` with PEP 696 defaults, the typed `CurrentUser` / `VerifiedUser` / `SuperUser` dependencies, and the adapter mixin surfaces = are now visible to mypy, pyright, and IDE language servers when the library is installed from PyPI. Previously the annotations existed internally but were treated as `Any` by consumers.
- `mypy` added to the dev dependency group for contributors who want to type-check locally. Not yet enforced in CI = strict mode has a backlog of ~190 existing errors (mostly missing return annotations, mixin-method lookups through `AbstractUserAdapter`, and passkey-config narrowings) that will be cleaned up in a dedicated typed-hardening release.

## 0.9.0

### Breaking changes

- **Lockout now returns `401`** instead of `423 Locked`. Clients that branched on `423` to render a "your account is locked" UI will silently fall into the generic credentials-error path. The change is deliberate = see Security below.
- **Email lookup is now case-insensitive.** On case-sensitive database collations (MySQL default, SQL Server), rows registered with mixed-case emails (`Alice@X.com`) will stop matching logins submitted in a different case. Run a one-off `UPDATE fullauth_users SET email = LOWER(TRIM(email))` before upgrading. PostgreSQL/SQLite with default collations are unaffected.

### Security

- Emails are now normalised (stripped + lowercased) on create, update, and lookup in both built-in adapters. Previously `Alice@X.com` and `alice@X.com` could register as separate accounts on case-sensitive collations (MySQL default, SQL Server).
- Login now returns the same generic `401 Could not validate credentials` response for a locked account as for a wrong password. Previously a `423 Locked` status let an attacker distinguish "email exists and is locked out" from "wrong password" = an enumeration signal once they'd exhausted the lockout counter on a target email. The `AccountLockedError` message no longer includes the identifier (cleaner logs too).
- Opt-in `PREVENT_REGISTRATION_ENUMERATION` setting (default `False`). When `True`, `/register` always responds `202` + `{"detail": "If this email isn't already registered, a verification email has been sent."}` whether the email was taken or not = attackers can't probe the user table through the registration endpoint. Off by default to keep the `201` + user / `409` conflict shape that most client apps expect.

### Fixed

- `BearerBackend` accepts any case of the `Bearer` auth scheme (`Bearer`, `bearer`, `BEARER`, mixed) per RFC 7235. Clients that sent a lowercase scheme were previously rejected with a 401.
- `require_role` tolerates a `UserSchema` subclass with no `roles` field = returns a clean `403` instead of `AttributeError` / `500`. The default schema doesn't ship with `roles`; apps using RBAC still need to add it to their custom schema.
- `hash_password(..., algorithm="bcrypt")` rejects passwords over 72 UTF-8 bytes with `InvalidPasswordError` instead of silently truncating. bcrypt's built-in truncation would otherwise cause subtle lockouts if an app later migrated to argon2id.
- SQLModel `UserBase.hashed_password` column is now `Text`. Argon2id hashes are ~97 characters; MySQL / MSSQL default `VARCHAR(255)` was still fine but the column type is explicit now, matching the SQLAlchemy adapter.
- `FullAuthConfig` validates passkey settings at construction time when `PASSKEY_ENABLED=True` = empty `PASSKEY_RP_ID` / `PASSKEY_ORIGINS`, RP ID with scheme or path, origin without scheme, and Redis backend without `REDIS_URL` all raise at config creation instead of surfacing as 500s at first request.

## 0.8.0

### Security

- OAuth auto-link-by-email now requires `info.email_verified=True` from the provider when an account with that email already exists. Without this gate, any provider that returns an unverified email (e.g. GitHub secondary addresses) could be used to hijack an existing account by registering the provider with the victim's email.
- Cookie backend's `delete_token` now matches the same `secure`/`samesite`/`path`/`domain` attributes used on set. Browsers ignore (or reject, for `SameSite=None`) a deletion that doesn't match = logout previously left the cookie in place on some setups.
- Refresh-token revocation is now an atomic compare-and-swap (`UPDATE ... WHERE revoked=false`). Two concurrent refresh calls with the same token can no longer both succeed by racing the old stored-state check. `AbstractUserAdapter.revoke_refresh_token` now returns `bool` = custom adapters should honour the CAS semantics.
- `create_user` catches `IntegrityError` from duplicate-email races and raises `UserAlreadyExistsError`. The register flow's pre-check only guards the common case; concurrent signups used to surface as 500s.
- OAuth account table now has a composite unique constraint on `(provider, provider_user_id)`. Existing SQL users should autogenerate an Alembic migration to add it. `create_oauth_account` now returns the existing row on concurrent-insert collisions instead of erroring.
- Password-reset and email-verification tokens now use their own TTLs (`PASSWORD_RESET_EXPIRE_MINUTES`, default 15; `EMAIL_VERIFY_EXPIRE_MINUTES`, default 1440) instead of inheriting `ACCESS_TOKEN_EXPIRE_MINUTES`. A production tweak to access-token lifetime for mobile clients no longer silently extends the window in which a stolen password-reset email grants an account takeover.

### Breaking changes

- **Models split into packages** = `adapters/sqlmodel/models.py` and `adapters/sqlalchemy/models.py` are now `models/` directories with `base.py`, `role.py`, `permission.py`, `oauth.py`. Old import paths (`from fastapi_fullauth.adapters.sqlmodel.models import ...`) still work via `__init__.py` re-exports. New selective imports: `from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord`.
- **`roles` removed from default `UserSchema`** = apps that use roles should extend `UserSchema` with `roles: list[str] = Field(default_factory=list)`. Apps without roles are unaffected.
- **Admin router auto-skipped** when adapter doesn't implement `RoleAdapterMixin`. OAuth/passkey routers auto-skipped similarly.
- **`AbstractUserAdapter.revoke_refresh_token` now returns `bool`** = custom adapters need to return `True` only when the token actually transitioned from not-revoked to revoked (CAS semantics).

### Added

- **Composable models** = only imported model groups register tables. Apps that don't need roles/permissions/oauth skip those tables entirely.
- **Selective migration helper** = `include_fullauth_models("sqlmodel", include=["base", "role"])` imports only specified model groups for Alembic.
- **`exclude_routers` param on `init_app()`** = `fullauth.init_app(app, exclude_routers=["admin"])` to skip routers you don't need.
- **`bind(app)` method** = bind FullAuth to a FastAPI app for composable router usage. Called automatically by `init_app()` and `init_middleware()`.
- **`init_middleware()` method** = wire up middleware independently when using composable routers.
- **`RouterName` type** = `Literal["auth", "profile", "verify", "admin", "oauth"]` for type-safe router exclusion.
- **`AuthRateLimiter` class** = per-route auth rate limiting extracted from FullAuth into its own class.
- **`exchange_oauth_code()`, `link_or_create_user()`, `issue_oauth_tokens()`** = OAuth callback split into composable flow functions. `oauth_callback()` still works as before (delegates to the three).
- **`register_lockout_backend()`** = register custom lockout backends for `create_lockout()` factory.
- **`register_rate_limiter_backend()`** = register custom rate limiter backends for `create_rate_limiter()` factory.
- **Passkey (WebAuthn) authentication** = passwordless login with fingerprint, Face ID, security keys. Register, authenticate, list, and delete passkeys. Requires `pip install fastapi-fullauth[passkey]` and `PASSKEY_ENABLED=True`.
- **`ChallengeStore`** = abstract challenge store with InMemory and Redis backends for WebAuthn flows.
- **`PasskeyAdapterMixin`** = adapter mixin for passkey credential persistence.
- **Adapter mixins** = `AbstractUserAdapter` split into composable interfaces: `RoleAdapterMixin`, `PermissionAdapterMixin`, `OAuthAdapterMixin`, `PasskeyAdapterMixin`. Custom adapters implement only what they need. Built-in adapters inherit all mixins (backward compatible).

### Changed

- Adapter model imports are lazy = importing the adapter no longer registers role/permission/oauth tables
- Rate limiting extracted from FullAuth `__init__` into `AuthRateLimiter`
- SQLModelAdapter `session_maker` type hint accepts both session types cleanly
- `TokenClaimsBuilder` and `RouterName` moved to `types.py`
- `init_app()` and `init_middleware()` are now idempotent. Calling either twice on the same FastAPI app emits a `UserWarning` and is a no-op. Previously a second call (e.g. `init_app(app)` followed by a stray `init_middleware(app)`) doubled the middleware stack = duplicate security headers, two rate-limiter instances halving the effective limit, and a CSRF layer validating another CSRF layer's cookies.
- JWT decode now tolerates clock drift between services via `JWT_LEEWAY_SECONDS` (default 30). Eliminates sporadic 401s caused by ±30 s skew between client and server clocks or across load-balanced instances.
- `FullAuthConfig` reads `.env` in the current working directory by default (`env_file=".env"`), and ignores unknown `FULLAUTH_*` vars instead of erroring (`extra="ignore"`). Local dev "just works" without passing `_env_file=".env"` explicitly. Cloud deployments are unaffected = pydantic-settings' precedence is init kwargs → `os.environ` → `.env` → defaults, so platform-injected env vars always win, and a missing `.env` is a silent no-op. Use `FullAuthConfig(_env_file="…")` or a `SettingsConfigDict` subclass to read a different file.

## 0.7.0

### Breaking changes

- **InMemory adapter removed** = use SQLModel + SQLite for prototyping instead.
- **`UserID` is now `UUID`** (was `str | int | UUID`) = all adapter methods, `RefreshToken.user_id`, `OAuthAccount.user_id`, and `RoleAssignment.user_id` are now `UUID`.
- **OAuth providers passed as objects** = `FullAuth(providers=[GoogleOAuthProvider(...)])` replaces `OAUTH_PROVIDERS` dict in config. `OAuthProviderConfig` removed.
- **`OAuthProvider` simplified** = only `redirect_uris: list[str]` (removed singular `redirect_uri`). `get_redirect_uri()` removed.
- **`redirect_uri` required in authorize URL** = clients must pass `?redirect_uri=` in the OAuth authorize request.
- **`include_user_in_login` moved to config** = use `FullAuthConfig(INCLUDE_USER_IN_LOGIN=True)` or `FULLAUTH_INCLUDE_USER_IN_LOGIN=true` env var instead of `FullAuth(include_user_in_login=True)`.
- **Login response always includes `user` field** = when `INCLUDE_USER_IN_LOGIN=False`, `user` is `null` (previously the key was absent). When `True`, `user` contains the full user schema object.

### Added

- **Redis lockout backend** = `LOCKOUT_BACKEND="redis"` for multi-worker deployments
- `LOCKOUT_ENABLED` config = disable account lockout entirely (`False`)
- `INCLUDE_USER_IN_LOGIN` config = include user object in login/OAuth callback response
- `LoginResponse` dynamic model = login and OAuth callback routes now have proper `response_model` with typed `user` field matching the configured user schema
- `validate_profile_updates` flow = profile field filtering extracted from router to `flows/update_profile.py`
- `NoValidFieldsError`, `UnknownFieldsError` exceptions for profile update validation
- `change_password` flow = business logic extracted from profile router
- `PROTECTED_FIELDS` ClassVar on `UserSchema` = users can extend in subclasses
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
- Removed `str(user.id)` / `str(row.user_id)` conversions = UUID used directly

### Removed

- `InMemoryAdapter` and `examples/memory_app/`
- `OAuthProviderConfig` from config
- `OAUTH_PROVIDERS` from `FullAuthConfig`
- `FullAuth._build_oauth_providers()` and `_OAUTH_PROVIDER_REGISTRY`
- `OAuthProvider.get_redirect_uri()` method
- `rbac/` package (was empty, just re-exported from `dependencies`)

## 0.6.0

### Breaking changes

- **Config-only API** = `FullAuth` no longer accepts `secret_key=`, `**config_kwargs`, or positional `config`. Pass `config=FullAuthConfig(SECRET_KEY="...")` or set `FULLAUTH_SECRET_KEY` env var. All params are keyword-only.
- **`enabled_routes` removed** = replaced by composable routers. Include only the routers you need instead of filtering route names.
- **`RouteName` type removed** = no longer needed with composable routers.
- **`configure_hasher()` removed** = hash algorithm is now passed explicitly from config through flows. No more global mutable state.
- **Schema auto-derivation removed** = `_derive_user_schema()` and `_resolve_create_schema()` deleted from all adapters and FullAuth. Define your own schemas extending `UserSchema` / `CreateUserSchema` and pass them to the adapter.
- **`create_user_schema` moved to adapter** = pass it to the adapter, not FullAuth: `InMemoryAdapter(user_schema=MyUser, create_user_schema=MyCreate)`.

### Added

- **Generic type parameters** = `AbstractUserAdapter[UserSchemaType, CreateUserSchemaType]`, `FullAuth[UserSchemaType, CreateUserSchemaType]` with PEP 696 defaults for full type safety
- **Composable routers** = `fullauth.auth_router`, `fullauth.profile_router`, `fullauth.verify_router`, `fullauth.admin_router`, `fullauth.oauth_router`. Each lazily created, include only what you need
- **Typed dependency factories** = `get_current_user_dependency(MyUser)`, `get_verified_user_dependency(MyUser)`, `get_superuser_dependency(MyUser)` for custom schema type safety
- `create_blacklist(config)` = extracted from FullAuth to `core/tokens.py`
- `create_rate_limiter(config, max, window)` = extracted from FullAuth to `protection/ratelimit.py`
- `UserSchemaType`, `CreateUserSchemaType` TypeVars exported from top-level package
- `UserSchema`, `CreateUserSchema` base classes exported from top-level package

### Changed

- **Router split** = 613-line monolithic `create_auth_router()` split into `create_auth_router()` (login/register/logout/refresh), `create_profile_router()` (me/update/delete/change-password), `create_verify_router()` (email verify/password reset), `create_admin_router()` (roles/permissions)
- **FullAuth slimmed** = factory methods extracted, composable router properties added, `_OAUTH_PROVIDER_REGISTRY` stays on class for now
- `fullauth.router` still works as before (composes all sub-routers), `fullauth.init_app(app)` unchanged
- `hash_password()` and `password_needs_rehash()` now accept explicit `algorithm` parameter (default `argon2id`)
- Shared request/response models extracted to `router/_models.py`
- RBAC permissions (`require_role`, `require_permission`) available via `fastapi_fullauth.dependencies`

### Removed

- `FullAuth._resolve_create_schema()` = auto-derivation of create schema from ORM model
- `SQLModelAdapter._derive_user_schema()` = auto-derivation of user schema
- `SQLAlchemyAdapter._derive_user_schema()` = auto-derivation of user schema
- `_SA_TYPE_MAP` and `_get_sa_type_map()` = SQLAlchemy type mapping for auto-derivation
- `FullAuth._create_blacklist()` = moved to `core/tokens.create_blacklist()`
- `FullAuth._create_rate_limiter()` = moved to `protection.ratelimit.create_rate_limiter()`
- `configure_hasher()` and `_algorithm` global from `core/crypto.py`

## 0.5.0

### Added

- **Structured logging** across all auth flows, security middleware, and OAuth = failed logins, account lockouts, token reuse, CSRF violations, rate limit hits, role changes, and account deletions are all logged via `logging.getLogger("fastapi_fullauth.*")`
- **Documentation site** = MkDocs with Material theme, auto-deployed to GitHub Pages via CI
- **Proxy-aware rate limiting** = new `TRUSTED_PROXY_HEADERS` config to read real client IPs from `X-Forwarded-For` and similar headers
- **SQLAlchemy example app** (`examples/sqlalchemy_app/`)
- **`update_user` field validation** = rejects unknown fields with 422 instead of passing them to the DB
- SQLModel adapter now accepts both SQLModel's and SQLAlchemy's `AsyncSession`
- `OAuthAccountRecord` exported from `fastapi_fullauth.adapters.sqlmodel`

### Fixed

- **OAuth state token TTL was ignored** = `OAUTH_STATE_EXPIRE_SECONDS` config had no effect; state tokens used `ACCESS_TOKEN_EXPIRE_MINUTES` (30 min) instead of the configured 5 min
- **Refresh token reuse detection race condition** = two concurrent `/refresh` requests could both succeed before either revoked the token; added explicit blacklist check before issuing new tokens
- **OAuth error messages leaked provider internals** = raw API responses from Google/GitHub were exposed in HTTP error details; now logged internally and replaced with generic messages

### Changed

- README rewritten with centered hero layout, badges, and documentation links
- Documentation URL updated in `pyproject.toml` to point to GitHub Pages

## 0.4.0

### Added

- **OAuth2 social login** = Google and GitHub out of the box, extensible for custom providers
  - `GET /oauth/{provider}/authorize` = get authorization URL
  - `POST /oauth/{provider}/callback` = exchange code for JWT tokens
  - `GET /oauth/providers` = list configured providers
  - `GET /oauth/accounts` = list linked OAuth accounts
  - `DELETE /oauth/accounts/{provider}` = unlink a provider (with lockout prevention)
- `OAuthProvider` abstract base class for implementing custom providers
- `OAuthAccount` and `OAuthUserInfo` types
- `OAuthAccountRecord` / `OAuthAccountModel` for SQLModel and SQLAlchemy adapters
- OAuth adapter methods on all adapters (memory, SQLModel, SQLAlchemy)
- `OAUTH_PROVIDERS`, `OAUTH_STATE_EXPIRE_SECONDS`, `OAUTH_AUTO_LINK_BY_EMAIL` config fields
- `after_oauth_login` hook event
- `oauth` optional dependency group (`pip install fastapi-fullauth[oauth]`)
- Auto-link OAuth to existing user by email (configurable)
- Auto-verify email when provider confirms it
- Lockout prevention = can't unlink last login method
- Multiple `redirect_uris` per OAuth provider = supports web, mobile, and production frontends from one config. Client passes `?redirect_uri=` on authorize, validated against allowed list.

## 0.3.0

### Breaking changes

- **`create_refresh_token` returns `RefreshTokenMeta`** = previously returned a plain `str`. Now returns a `NamedTuple` with `.token`, `.expires_at`, `.family_id`. Callers that used the raw string must access `.token`.
- **`create_token_pair` returns `tuple[str, RefreshTokenMeta]`** = second element is now `RefreshTokenMeta` instead of `str`.
- **`revoke_all_user_refresh_tokens` is now required** on custom adapters = new abstract method on `AbstractUserAdapter`.

### Added

- `current_superuser` dependency and `SuperUser` annotated type
- `CurrentUser`, `VerifiedUser`, `SuperUser` annotated types in `dependencies.current_user` for cleaner route signatures
- `RefreshTokenMeta` named tuple = avoids decoding freshly created tokens just to read `expires_at` and `family_id`
- `FullAuth.get_custom_claims(user)` = moved custom claims logic from router into the class, with validation against reserved JWT keys (`sub`, `exp`, `type`, etc.)
- `revoke_all_user_refresh_tokens(user_id)` on all adapters = bulk session revocation
- Session revocation on password reset, password change, and account deletion
- `configure_hasher()` = wires `PASSWORD_HASH_ALGORITHM` config to the actual hasher; supports `argon2id` and `bcrypt`
- Automatic password rehash on login when hash algorithm or params have changed
- Register now checks uniqueness on `login_field` (not just email) when `login_field != "email"`
- `InMemoryBlacklist` now respects `ttl_seconds` = expired entries are evicted on lookup
- `RateLimiter` evicts keys with empty timestamp lists to prevent unbounded dict growth
- `description` parameter on all route decorators for Swagger docs

### Fixed

- `current_active_verified_user` was missing `payload.type != "access"` check = refresh tokens could pass through
- Purpose tokens (password reset, email verify) could be used as regular access tokens = `current_user` now rejects tokens with `extra.purpose`
- Duplicate token decode + user lookup across dependencies, router endpoints, and admin routes = consolidated into reusable `current_user` dependency chain
- Duplicate `roles` + `extra_claims` fetch in refresh route = pulled above the if/else branch
- Login flow fetched the user from DB twice (once in router, once in `login()`) = now accepts pre-fetched user
- Unused `request: Request` parameters in dependencies and routes
- Removed duplicate docstrings on routes (kept `description=` on decorators)
- `require_permission` was a full copy of `require_role` = now delegates to it

### Internal

- Route order follows auth lifecycle: register → login → refresh → logout → user → email/password → admin
- `require_role` / `require_permission` use `Depends(current_user)` instead of duplicating token logic
- Removed `_get_custom_claims` module-level function from router

## 0.2.0

### Breaking changes

- **JSON login** = `POST /login` now accepts `{"email": "...", "password": "..."}` instead of form data. Swagger auth uses bearer token input instead of username/password form.
- **No default User model** = SQLModel and SQLAlchemy adapters no longer ship a concrete `User`/`UserModel` table class. Users must define their own model from `UserBase`. This eliminates relationship conflicts when subclassing.
- **`user_model` is required** = `SQLModelAdapter(session_maker, user_model=MyUser)` = no default.
- **Removed `min_length=8`** from `CreateUserSchema` = password length is now fully controlled by `PasswordValidator` and `PASSWORD_MIN_LENGTH` config.
- **`SQLAlchemyAdapter` renamed `UserModel` to `UserBase`** = import `UserBase` instead.

### Added

- `POST /auth/change-password` = verifies current password, validates new
- `PATCH /auth/me` = update profile with protected field filtering
- `DELETE /auth/me` = self-deletion
- `expires_in` in login/refresh responses
- Per-IP auth rate limiting on login, register, password-reset (`AUTH_RATE_LIMIT_*` config)
- `LOGIN_FIELD` config = login by email, username, phone, or any model field
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
