# Adapters

## What is an adapter

Adapters decouple the authentication logic from the database. The library defines abstract interfaces for user management, token storage, roles, OAuth, and passkeys. Concrete adapters implement these interfaces for specific ORMs.

The library ships adapters for SQLModel and SQLAlchemy. You can write your own for MongoDB, Tortoise ORM, or any other data store by implementing the abstract interface.

## Available adapters

| Adapter | Backend | Install |
|---------|---------|---------|
| [SQLModel](sqlmodel.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlmodel]` |
| [SQLAlchemy](sqlalchemy.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlalchemy]` |

## Choosing an adapter

- **SQLModel** = recommended for most projects. Clean model definitions, good type support. Use SQLite for prototyping.
- **SQLAlchemy** = use if your project already uses SQLAlchemy's declarative base.

Both adapters support the same features. The difference is in model definition style.

## Adapter architecture

### Core interface

`AbstractUserAdapter` defines the contract every adapter must implement:

- **User CRUD**: `get_user_by_id()`, `get_user_by_email()`, `get_user_by_field()`, `create_user()`, `update_user()`, `delete_user()`
- **Passwords**: `get_hashed_password()`, `set_password()`
- **Refresh tokens**: `store_refresh_token()`, `get_refresh_token()`, `revoke_refresh_token()`, `revoke_refresh_token_family()`, `revoke_all_user_refresh_tokens()`
- **Verification**: `set_user_verified()`, `get_user_roles()`

### Optional mixins

Mixins add capabilities to your adapter. The library checks `isinstance()` at startup to decide which routers to mount. If your adapter doesn't inherit a mixin, the corresponding feature is simply not available - no dead endpoints, no errors.

| Mixin | Enables | Required model |
|-------|---------|----------------|
| `RoleAdapterMixin` | Admin router, `require_role()` | `RoleMixin` |
| `PermissionAdapterMixin` | `require_permission()` | `PermissionMixin`, `RolePermissionMixin` |
| `OAuthAdapterMixin` | OAuth router | `OAuthAccountMixin` |
| `PasskeyAdapterMixin` | Passkey router | `PasskeyMixin` |

## Model mixins

The library provides SQLAlchemy declarative mixins for database tables. You subclass them to create concrete tables in your app's metadata. The library never ships its own tables - your app owns every table definition, which means Alembic migrations work naturally.

| Mixin | Default table name | Purpose |
|-------|-------------------|---------|
| `UserMixin` | `fullauth_users` | User accounts |
| `RefreshTokenMixin` | `fullauth_refresh_tokens` | Stored refresh tokens |
| `RoleMixin` | `fullauth_roles` | User-role assignments |
| `OAuthAccountMixin` | `fullauth_oauth_accounts` | Linked OAuth providers |
| `PasskeyMixin` | `fullauth_passkeys` | WebAuthn credentials |
| `PermissionMixin` | `fullauth_permissions` | Permission definitions |
| `RolePermissionMixin` | `fullauth_role_permissions` | Role-permission mappings |

You only need the mixins for features you use. A minimal setup needs just `UserMixin` and `RefreshTokenMixin`.

## Custom adapters

Subclass `AbstractUserAdapter` for core auth. Add mixins for the features you need:

```python
from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    RoleAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
)

class MyAdapter(AbstractUserAdapter, RoleAdapterMixin, OAuthAdapterMixin):
    async def get_user_by_id(self, user_id): ...
    async def get_user_by_email(self, email): ...
    async def create_user(self, data, hashed_password): ...
    # ... implement all abstract methods
```

### Key method contracts

Most methods are straightforward CRUD. A few have important semantics:

**`revoke_refresh_token(token_str) -> bool`**: Atomically flip the token from `revoked=False` to `revoked=True`. Returns `True` if this call performed the flip (caller won the race), `False` if the token was already revoked. This compare-and-swap behavior is critical for refresh token reuse detection. If it returns `False`, the library revokes the entire token family.

**`update_passkey_sign_count(credential_id, new_count) -> bool`**: Only advance the sign count if `new_count > stored_count`. Returns `True` on success, `False` if the stored count is already higher (clone detection).

**`get_user_roles(user_id) -> list[str]`**: Returns the user's role names. This is called at token creation time; the roles are embedded in the JWT.

See the [source of AbstractUserAdapter](https://github.com/mdfarhankc/fastapi-fullauth/blob/main/fastapi_fullauth/adapters/base.py) for the full interface.

## Custom schemas

Define your own user schemas by extending `UserSchema` and `CreateUserSchema`, then pass them to the adapter:

```python
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""

class MyCreateSchema(CreateUserSchema):
    display_name: str = ""

adapter = SQLModelAdapter(
    session_factory=session_factory,
    user_model=User,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

The `UserSchema` base class defines `PROTECTED_FIELDS` - a set of fields that can't be updated via `PATCH /me`. By default this includes `id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `roles`, `password`, `created_at`, and `refresh_tokens`. If your custom schema adds fields that should also be protected from profile updates, extend this set.

If your app uses roles, add `roles` to your custom schema:

```python
class MyUserSchema(UserSchema):
    roles: list[str] = Field(default_factory=list)
```
