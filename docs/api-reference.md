# API Reference

Quick reference for the main classes, types, and functions.

## FullAuth

The main auth manager. Central entry point for the library.

```python
from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(
    adapter=adapter,                # required — database adapter
    config=FullAuthConfig(...),     # FullAuthConfig object (see Configuration)
    providers=None,                 # list of OAuthProvider instances
    backends=None,                  # [BearerBackend()] by default
    password_validator=None,        # PasswordValidator instance
    on_create_token_claims=None,    # async callback for custom JWT claims
)
```

### Methods

| Method | Description |
|--------|-------------|
| `init_app(app, *, auto_middleware=True, exclude_routers=None)` | Mount routes and middleware on a FastAPI app. Pass `exclude_routers=["admin"]` to skip specific routers. |
| `bind(app)` | Bind FullAuth to a FastAPI app (sets `app.state.fullauth`). Required when using composable routers without `init_app()`. |
| `init_middleware(app)` | Wire up middleware from config. Also calls `bind()` if not already done. |
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

Returned by login and OAuth callback routes. Extends `TokenPair` with an optional `user` field. The `user` field contains the full user schema object when `INCLUDE_USER_IN_LOGIN=True`, otherwise `null`. The user type matches your configured user schema (e.g., `MyUserSchema`).

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
    CurrentUser,        # Annotated type — any authenticated user
    VerifiedUser,       # Annotated type — verified email required
    SuperUser,          # Annotated type — superuser required
    current_user,       # function form of CurrentUser
    require_role,       # require_role("admin", "editor")
    require_permission, # require_permission("posts:edit", "posts:delete")
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
