# API Reference

Quick reference for the main classes, types, and functions.

## FullAuth

The main auth manager. Central entry point for the library.

```python
from fastapi_fullauth import FullAuth

fullauth = FullAuth(
    config=None,                    # FullAuthConfig object (mutually exclusive with kwargs)
    adapter=adapter,                # required — database adapter
    secret_key=None,                # shortcut for config.SECRET_KEY
    backends=None,                  # [BearerBackend()] by default
    password_validator=None,        # PasswordValidator instance
    enabled_routes=None,            # whitelist of route names, None = all
    include_user_in_login=False,    # include user data in login response
    create_user_schema=None,        # custom registration schema
    on_create_token_claims=None,    # async callback for custom JWT claims
    **config_kwargs,                # any FullAuthConfig field as lowercase
)
```

### Methods

| Method | Description |
|--------|-------------|
| `init_app(app, auto_middleware=True)` | Mount routes and middleware on a FastAPI app |
| `hooks.on(event, callback)` | Register an event hook |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `config` | `FullAuthConfig` | Active configuration |
| `adapter` | `AbstractUserAdapter` | Database adapter |
| `token_engine` | `TokenEngine` | JWT creation/validation engine |
| `router` | `APIRouter` | The auth router (lazy-created) |

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
    RouteName,          # Literal type of all route names
)
```

### UserSchema

```python
class UserSchema(BaseModel):
    id: str | int | UUID
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = []
```

### TokenPair

```python
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int | None = None
```

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

### RouteName

```python
RouteName = Literal[
    "login", "logout", "register", "refresh",
    "verify-email", "password-reset", "me", "verified-me",
    "change-password", "update-profile", "delete-account",
]
```

## Dependencies

```python
from fastapi_fullauth.dependencies import (
    CurrentUser,        # Annotated type — any authenticated user
    VerifiedUser,       # Annotated type — verified email required
    SuperUser,          # Annotated type — superuser required
    current_user,       # function form of CurrentUser
    require_role,       # require_role("admin", "editor")
    require_permission, # alias for require_role
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
