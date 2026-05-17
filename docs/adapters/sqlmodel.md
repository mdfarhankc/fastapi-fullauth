# SQLModel Adapter

The recommended adapter for most projects.

## Installation

```bash
pip install fastapi-fullauth[sqlmodel]
```

## Setup

### 1. Define your tables

Each table you use is a concrete class you define by combining a `*Mixin` with `table=True`. Only subclass the mixins for features you actually use.

```python
from sqlmodel import Field, Relationship
from fastapi_fullauth.models.sqlmodel import (
    RefreshTokenMixin, RoleMixin, UserMixin, UserRoleMixin,
)


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class Role(RoleMixin, table=True):
    pass


class UserRole(UserRoleMixin, table=True):
    pass


class User(UserMixin, table=True):
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)
    roles: list[Role] = Relationship(link_model=UserRole)
    refresh_tokens: list[RefreshToken] = Relationship()
```

`UserMixin` provides these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUID` (UUID7) | Primary key, auto-generated |
| `email` | `str` | Unique, indexed |
| `hashed_password` | `str` | Password hash |
| `has_usable_password` | `bool` | False for OAuth-only users |
| `is_active` | `bool` | Account active flag |
| `is_verified` | `bool` | Email verified flag |
| `is_superuser` | `bool` | Superuser flag |
| `created_at` | `datetime` | UTC creation timestamp |

### 2. Create the adapter

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

engine = create_async_engine("sqlite+aiosqlite:///app.db")
session_maker = async_sessionmaker(engine, expire_on_commit=False)
```

You can use either SQLAlchemy's `AsyncSession` or SQLModel's `AsyncSession`:

=== "SQLAlchemy AsyncSession"

    ```python
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///app.db")
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    ```

=== "SQLModel AsyncSession"

    ```python
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlmodel.ext.asyncio.session import AsyncSession

    engine = create_async_engine("sqlite+aiosqlite:///app.db")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    ```

Then create the adapter — pass every concrete class you defined:

```python
from fastapi_fullauth.adapters import SQLModelAdapter

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    role_model=Role,
    user_role_model=UserRole,
)
```

Required kwargs: `user_model`, `refresh_token_model`. Optional kwargs (required if you use the matching feature): `role_model`, `user_role_model`, `permission_model`, `role_permission_model`, `oauth_account_model`, `passkey_model`. Calling a feature method without its model raises `RuntimeError`.

### 3. Wire into FullAuth

```python
from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="your-secret-key",
    ),
)
```

## Tables created

Tables are created based on which mixins you subclass:

| Group | Tables | Mixins |
|-------|--------|--------|
| Core (always) | `fullauth_users`, `fullauth_refresh_tokens` | `UserMixin`, `RefreshTokenMixin` |
| Roles | `fullauth_roles`, `fullauth_user_roles` | `RoleMixin`, `UserRoleMixin` |
| Permissions | `fullauth_permissions`, `fullauth_role_permissions` | `PermissionMixin`, `RolePermissionMixin` |
| OAuth | `fullauth_oauth_accounts` | `OAuthAccountMixin` |
| Passkeys | `fullauth_passkeys` | `PasskeyMixin` |

## Custom schemas

Define your own schemas and pass them to the adapter:

```python
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""
    phone: str = ""

class MyCreateSchema(CreateUserSchema):
    display_name: str = ""

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

If you don't pass custom schemas, the base `UserSchema` and `CreateUserSchema` are used.

## OAuth support

The SQLModel adapter implements `OAuthAdapterMixin`. Define an `OAuthAccount` from `OAuthAccountMixin` and pass it to the adapter as `oauth_account_model=...`.
