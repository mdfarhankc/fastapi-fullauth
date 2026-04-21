# API reference — cheatsheet

Single-page lookup for the public API. Deep details live in the topic-specific reference files.

## Top-level imports

```python
from fastapi_fullauth import (
    FullAuth,
    FullAuthConfig,
    PasswordValidator,
)
```

## Adapters

```python
from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
)
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter
```

### Model base classes

```python
# sqlmodel
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord

# sqlalchemy
from fastapi_fullauth.adapters.sqlalchemy.models.base import UserBase, FullAuthBase, RefreshTokenModel
```

### Opt-in model submodules

Importing registers the corresponding tables:

- `.models.role` — `Role`, `UserRoleLink` (sqlmodel) / `RoleModel`, `user_role_table` (sqlalchemy)
- `.models.permission` — `Permission`, `RolePermissionLink`
- `.models.oauth` — `OAuthAccountRecord` / `OAuthAccountModel`
- `.models.passkey` — `PasskeyRecord` / `PasskeyModel`

## Types

```python
from fastapi_fullauth.types import (
    UserSchema,                # response/validation schema for users
    CreateUserSchema,          # registration body
    UserID,                    # UUID alias
    UserSchemaType,            # TypeVar bound=UserSchema, default=UserSchema
    CreateUserSchemaType,      # TypeVar bound=CreateUserSchema, default=CreateUserSchema
    TokenPair,                 # {access_token, refresh_token, token_type, expires_in}
    TokenPayload,              # decoded JWT
    RefreshToken,              # persisted refresh token
    RefreshTokenMeta,          # refresh token + metadata at creation time
    OAuthAccount,              # OAuth account row
    OAuthUserInfo,             # what a provider returns
    PasskeyCredential,         # passkey row
    RouterName,                # Literal["auth", "profile", "verify", "admin", "oauth", "passkey"]
    TokenClaimsBuilder,        # async callable for custom JWT claims
)
```

## Dependencies

```python
from fastapi_fullauth.dependencies import (
    current_user,                   # Annotated dep → UserSchema
    get_current_user_dependency,    # factory for custom UserSchema
    require_role,                   # require_role("admin")
    require_permission,             # require_permission("posts:create")
)
```

Usage:

```python
@app.get("/me")
async def me(user=Depends(current_user)): ...

@app.delete("/thing", dependencies=[Depends(require_role("admin"))])
async def delete_thing(): ...
```

## Backends

```python
from fastapi_fullauth.backends import (
    AbstractBackend,
    BearerBackend,        # default
    CookieBackend,        # opt-in
)
```

Pass `backends=[...]` to `FullAuth(...)`.

## OAuth

```python
from fastapi_fullauth.oauth import GithubProvider, GoogleProvider
from fastapi_fullauth.oauth.base import OAuthProvider

fullauth = FullAuth(
    config=...,
    adapter=...,
    providers=[GithubProvider(client_id=..., client_secret=..., redirect_uris=[...])],
)
```

## Flows (composable)

Direct use of the flow functions for custom routing:

```python
from fastapi_fullauth.flows.login import login
from fastapi_fullauth.flows.register import register
from fastapi_fullauth.flows.logout import logout
from fastapi_fullauth.flows.change_password import change_password
from fastapi_fullauth.flows.set_password import set_password
from fastapi_fullauth.flows.update_profile import update_profile
from fastapi_fullauth.flows.email_verify import (
    create_email_verification_token,
    verify_email,
)
from fastapi_fullauth.flows.password_reset import request_password_reset, reset_password
from fastapi_fullauth.flows.oauth import (
    oauth_callback,
    exchange_oauth_code,
    link_or_create_user,
    issue_oauth_tokens,
    generate_oauth_state,
    verify_oauth_state,
)
from fastapi_fullauth.flows.passkey import (
    begin_registration,
    complete_registration,
    begin_authentication,
    complete_authentication,
)
```

## Protection

```python
from fastapi_fullauth.protection.lockout import (
    LockoutManager,
    InMemoryLockoutManager,
    RedisLockoutManager,
    create_lockout,
    register_lockout_backend,
)
from fastapi_fullauth.protection.ratelimit import (
    AuthRateLimiter,
    RateLimiter,
    RedisRateLimiter,
    RateLimitMiddleware,
    create_rate_limiter,
    register_rate_limiter_backend,
)
```

## Core

```python
from fastapi_fullauth.core.tokens import TokenEngine, TokenBlacklist, InMemoryBlacklist, create_blacklist
from fastapi_fullauth.core.crypto import hash_password, verify_password, password_needs_rehash
from fastapi_fullauth.core.challenges import (
    ChallengeStore,
    InMemoryChallengeStore,
    RedisChallengeStore,
    create_challenge_store,
    register_challenge_store_backend,
)
from fastapi_fullauth.core.redis_blacklist import RedisBlacklist
```

## Middleware

```python
from fastapi_fullauth.middleware.csrf import CSRFMiddleware
from fastapi_fullauth.middleware.ratelimit import RateLimitMiddleware
from fastapi_fullauth.middleware.security_headers import SecurityHeadersMiddleware
```

Normally wired automatically by `fullauth.init_middleware(app)` or `fullauth.init_app(app, auto_middleware=True)`.

## Hooks

Every hook is an async callable registered on `fullauth.hooks`:

| Event                     | Signature                                       |
|---------------------------|-------------------------------------------------|
| `after_register`          | `(user: UserSchema) -> None`                    |
| `after_login`             | `(user: UserSchema) -> None`                    |
| `after_logout`            | `(user_id: UserID) -> None`                     |
| `after_oauth_login`       | `(user, provider: str, is_new_user: bool) -> None` |
| `after_oauth_register`    | `(user, user_info: OAuthUserInfo) -> None`      |
| `send_email_verification` | `(user: UserSchema, token: str) -> None`        |
| `send_password_reset`     | `(user: UserSchema, token: str) -> None`        |

```python
fullauth.hooks.on("send_email_verification", send_verification_email_async)
```

## Utilities

```python
from fastapi_fullauth.utils import (
    create_superuser,
    generate_secret_key,
    get_client_ip,
    normalize_email,
)
```

## Migrations helper

```python
from fastapi_fullauth.migrations import include_fullauth_models

include_fullauth_models("sqlmodel", include=["base", "role", "oauth"])
```

Valid `include` entries: `"base"`, `"role"`, `"permission"`, `"oauth"`, `"passkey"`.

## Exceptions

```python
from fastapi_fullauth.exceptions import (
    FullAuthError,              # base
    AuthenticationError,
    AccountLockedError,
    UserAlreadyExistsError,
    UserNotFoundError,
    TokenError,
    TokenExpiredError,
    TokenBlacklistedError,
    InvalidPasswordError,
    OAuthProviderError,
    UnknownFieldsError,
)

# Pre-built HTTPException instances the library raises
from fastapi_fullauth.exceptions import (
    CREDENTIALS_EXCEPTION,      # 401
    FORBIDDEN_EXCEPTION,        # 403
    USER_EXISTS_EXCEPTION,      # 409
    ACCOUNT_LOCKED_EXCEPTION,   # 423 — retained for backward compat; login now returns 401
    OAUTH_ERROR_EXCEPTION,      # 400
)
```

## Config — all settings

Grouped for readability. All read from env with `FULLAUTH_` prefix.

### Secrets / algorithm
- `SECRET_KEY: str | None = None`
- `ALGORITHM: str = "HS256"`

### Tokens
- `ACCESS_TOKEN_EXPIRE_MINUTES: int = 30`
- `REFRESH_TOKEN_EXPIRE_DAYS: int = 30`
- `REFRESH_TOKEN_ROTATION: bool = True`
- `JWT_LEEWAY_SECONDS: int = 30`
- `PASSWORD_RESET_EXPIRE_MINUTES: int = 15`
- `EMAIL_VERIFY_EXPIRE_MINUTES: int = 1440`

### Passwords
- `PASSWORD_HASH_ALGORITHM: "argon2id" | "bcrypt" = "argon2id"`
- `PASSWORD_MIN_LENGTH: int = 8`

### Login
- `LOGIN_FIELD: str = "email"`
- `INCLUDE_USER_IN_LOGIN: bool = False`

### Lockout
- `LOCKOUT_ENABLED: bool = True`
- `LOCKOUT_BACKEND: "memory" | "redis" = "memory"`
- `MAX_LOGIN_ATTEMPTS: int = 5`
- `LOCKOUT_DURATION_MINUTES: int = 15`

### Rate limits
- `RATE_LIMIT_ENABLED: bool = False`  (global middleware)
- `RATE_LIMIT_BACKEND: "memory" | "redis" = "memory"`
- `TRUSTED_PROXY_HEADERS: list[str] = []`
- `AUTH_RATE_LIMIT_ENABLED: bool = True`
- `AUTH_RATE_LIMIT_LOGIN: int = 5`
- `AUTH_RATE_LIMIT_REGISTER: int = 3`
- `AUTH_RATE_LIMIT_PASSWORD_RESET: int = 3`
- `AUTH_RATE_LIMIT_PASSKEY_AUTH: int = 10`
- `AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60`

### Redis
- `REDIS_URL: str | None = None`

### Blacklist
- `BLACKLIST_ENABLED: bool = True`
- `BLACKLIST_BACKEND: "memory" | "redis" = "memory"`

### Middleware
- `INJECT_SECURITY_HEADERS: bool = True`
- `CSRF_ENABLED: bool = False`
- `CSRF_SECRET: str | None = None`

### Cookies (when using `CookieBackend`)
- `COOKIE_NAME: str = "fullauth_access"`
- `COOKIE_SECURE: bool = True`
- `COOKIE_HTTPONLY: bool = True`
- `COOKIE_SAMESITE: "lax" | "strict" | "none" = "lax"`
- `COOKIE_DOMAIN: str | None = None`

### OAuth
- `OAUTH_STATE_EXPIRE_SECONDS: int = 300`
- `OAUTH_AUTO_LINK_BY_EMAIL: bool = True`

### Registration hardening
- `PREVENT_REGISTRATION_ENUMERATION: bool = False`

### Passkeys
- `PASSKEY_ENABLED: bool = False`
- `PASSKEY_RP_ID: str | None = None`
- `PASSKEY_RP_NAME: str | None = None`
- `PASSKEY_ORIGINS: list[str] = []`
- `PASSKEY_CHALLENGE_BACKEND: "memory" | "redis" = "memory"`
- `PASSKEY_CHALLENGE_TTL: int = 60`
- `PASSKEY_REQUIRE_USER_VERIFICATION: bool = True`

### Routing
- `API_PREFIX: str = "/api/v1"`
- `AUTH_ROUTER_PREFIX: str = "/auth"`
- `ROUTER_TAGS: list[str] = ["Auth"]`

## `FullAuth` public methods

- `init_app(app, *, auto_middleware=True, exclude_routers=None)` — routers + optional middleware. Idempotent.
- `init_middleware(app)` — middleware only. Idempotent.
- `bind(app)` — sets `app.state.fullauth`.
- `check_auth_rate_limit(route_name, client_ip)` — manual hit for custom routes.
- `get_custom_claims(user)` — returns extra JWT claims, validates reserved keys.
- Router properties: `router`, `auth_router`, `profile_router`, `verify_router`, `admin_router`, `oauth_router`, `passkey_router`.
- Attributes: `config`, `adapter`, `backends`, `token_engine`, `lockout`, `auth_rate_limiter`, `challenge_store`, `password_validator`, `on_create_token_claims`, `hooks`, `oauth_providers`.

## Built-in HTTP routes

Default prefix `/api/v1/auth`:

| Method | Path                              | Router   | Auth required |
|--------|-----------------------------------|----------|---------------|
| POST   | `/register`                       | auth     | no            |
| POST   | `/login`                          | auth     | no            |
| POST   | `/logout`                         | auth     | yes           |
| POST   | `/refresh`                        | auth     | (refresh)     |
| GET    | `/me`                             | profile  | yes           |
| PATCH  | `/me`                             | profile  | yes           |
| POST   | `/change-password`                | profile  | yes           |
| POST   | `/set-password`                   | profile  | yes           |
| POST   | `/password-reset/request`         | verify   | no            |
| POST   | `/password-reset/confirm`         | verify   | no            |
| POST   | `/verify/request`                 | verify   | yes           |
| POST   | `/verify/confirm`                 | verify   | no            |
| GET    | `/admin/users`                    | admin    | role:admin    |
| GET    | `/admin/users/{id}`               | admin    | role:admin    |
| PATCH  | `/admin/users/{id}`               | admin    | role:admin    |
| DELETE | `/admin/users/{id}`               | admin    | role:admin    |
| POST   | `/admin/users/{id}/roles`         | admin    | role:admin    |
| DELETE | `/admin/users/{id}/roles/{role}`  | admin    | role:admin    |
| POST   | `/admin/roles/{role}/permissions` | admin    | role:admin    |
| DELETE | `/admin/roles/{role}/permissions/{permission}` | admin | role:admin |
| GET    | `/oauth/providers`                | oauth    | no            |
| GET    | `/oauth/{provider}/authorize`     | oauth    | no            |
| POST   | `/oauth/{provider}/callback`      | oauth    | no            |
| GET    | `/oauth/accounts`                 | oauth    | yes           |
| DELETE | `/oauth/accounts/{provider}`      | oauth    | yes           |
| POST   | `/passkeys/register/begin`        | passkey  | yes           |
| POST   | `/passkeys/register/complete`     | passkey  | yes           |
| POST   | `/passkeys/authenticate/begin`    | passkey  | no            |
| POST   | `/passkeys/authenticate/complete` | passkey  | no            |
| GET    | `/passkeys`                       | passkey  | yes           |
| DELETE | `/passkeys/{id}`                  | passkey  | yes           |
