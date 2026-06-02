# API Reference

Quick reference for the main classes, types, and functions.

## FullAuth

The main auth manager. Central entry point for the library.

```python
from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(
    adapter=adapter,                # required = database adapter
    config=FullAuthConfig(...),     # FullAuthConfig object (see Configuration)
    providers=None,                 # list of OAuthProvider instances
    backends=None,                  # [BearerBackend()] by default
    password_validator=None,        # PasswordValidator instance
    on_create_token_claims=None,    # async callback for custom JWT claims
    login_response_schema=None,     # custom LoginResponse subclass
    message_response_schema=None,   # custom MessageResponse subclass
)
```

### Methods

| Method | Description |
|--------|-------------|
| `init_app(app, *, include_routers=None)` | Bind FullAuth to a FastAPI app and mount routes. `include_routers=None` (default) registers every available router; pass a list (e.g. `["auth", "profile"]`) to register only those. Does **not** wire middleware. |
| `bind(app)` | Bind FullAuth to a FastAPI app (sets `app.state.fullauth`). Required when using composable routers without `init_app()`. |
| `enforce_rate_limit(request, route_name)` | Resolve the client IP and apply the auth rate limit for `route_name`. |
| `aclose()` | Release pooled resources (Redis connections, OAuth HTTP clients). Registered on app shutdown by `init_app()`; call it yourself under a custom `lifespan`. Idempotent. |
| `hooks.on(event, callback)` | Register an event hook |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `config` | `FullAuthConfig` | Active configuration |
| `adapter` | `AbstractUserAdapter` | Database adapter |
| `token_engine` | `TokenEngine` | JWT creation/validation engine |
| `auth_router` | `APIRouter` | Login, logout, register, refresh routes |
| `profile_router` | `APIRouter` | Me, update profile, change password, delete account routes |
| `verify_router` | `APIRouter` | Email verification and password reset routes |
| `admin_router` | `APIRouter` | Role/permission management routes (superuser) |
| `oauth_router` | `APIRouter` | OAuth provider routes |
| `passkey_router` | `APIRouter` | Passkey WebAuthn routes |

## FullAuthConfig

```python
from fastapi_fullauth import FullAuthConfig
```

Pydantic Settings class. See [Configuration](configuration.md) for all options.

## Types

```python
from fastapi_fullauth.types import (
    UserSchema,         # base user response model
    CreateUserSchema,   # base registration model (email + password)
    TokenPair,          # access_token + refresh_token + token_type + expires_in
    TokenPayload,       # decoded JWT payload
    RefreshToken,       # stored refresh token record
    OAuthAccount,       # linked OAuth provider account
    OAuthUserInfo,      # user info from OAuth provider
)
```

### UserSchema

```python
class UserSchema(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False

    PROTECTED_FIELDS: ClassVar[set[str]] = {
        "id", "email", "hashed_password", "is_active",
        "is_verified", "is_superuser", "roles", "password",
        "created_at", "refresh_tokens",
    }
```

Extend `PROTECTED_FIELDS` in subclasses to protect custom sensitive fields from profile updates.

### TokenPair

```python
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int | None = None
```

### LoginResponse

Returned by login, OAuth callback, and passkey authenticate-complete routes. Extends `TokenPair` with a `user` field containing the full user schema object on every successful response. The user type matches your configured user schema (e.g., `MyUserSchema`).

### TokenPayload

```python
class TokenPayload(BaseModel):
    sub: str              # user ID
    exp: datetime         # expiry
    iat: datetime         # issued at
    jti: str              # unique token ID
    type: str             # "access" or "refresh"
    roles: list[str]      # user roles
    extra: dict[str, Any] # custom claims
    family_id: str | None # refresh token family
```

## Dependencies

```python
from fastapi_fullauth.dependencies import (
    current_user,                   # any authenticated user
    current_active_verified_user,   # verified email required
    current_superuser,              # superuser required
    get_fullauth,                   # access the FullAuth instance in a dependency
    require_role,                   # require_role("admin", "editor")
    require_permission,             # require_permission("posts:edit", "posts:delete")
)
```

## Exceptions

```python
from fastapi_fullauth.exceptions import (
    FullAuthError,                  # base exception
    AuthenticationError,            # login failed
    AuthorizationError,             # insufficient permissions
    TokenError,                     # invalid token
    TokenExpiredError,              # token expired
    TokenBlacklistedError,          # token was revoked
    UserAlreadyExistsError,         # duplicate registration
    UserNotFoundError,              # user not found
    InvalidPasswordError,           # password validation failed
    AccountLockedError,             # too many failed attempts
    OAuthError,                     # OAuth base error
    OAuthProviderError,             # provider-specific error
)
```

## Utilities

```python
from fastapi_fullauth import generate_secret_key, create_superuser

# generate a cryptographically secure secret key
key = generate_secret_key()

# create a superuser programmatically
user = await create_superuser(adapter, "admin@example.com", "password")
```

## Validators

```python
from fastapi_fullauth import PasswordValidator

validator = PasswordValidator(
    min_length=10,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=True,
    blocked_passwords=["password123"],
)
```
