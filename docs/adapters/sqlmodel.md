# SQLModel Adapter

The recommended adapter for most projects.

## Installation

```bash
pip install fastapi-fullauth[sqlmodel]
```

## Setup

### 1. Define your user model

```python
from sqlmodel import Field, Relationship
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink

class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    # add your custom fields
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    # relationships — import only what you need
    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()
```

Only tables for imported models are created. Skip `role` imports for apps that don't need roles.

`UserBase` provides these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUID` (UUID7) | Primary key, auto-generated |
| `email` | `str` | Unique, indexed |
| `hashed_password` | `str` | Password hash |
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

Then create the adapter:

```python
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
```

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

Tables are created based on which model groups you import:

| Group | Tables | Import from |
|-------|--------|-------------|
| Core (always) | `fullauth_users`, `fullauth_refresh_tokens` | `models.base` |
| Roles | `fullauth_roles`, `fullauth_user_roles` | `models.role` |
| Permissions | `fullauth_permissions`, `fullauth_role_permissions` | `models.permission` |
| OAuth | `fullauth_oauth_accounts` | `models.oauth` |

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
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

If you don't pass custom schemas, the base `UserSchema` and `CreateUserSchema` are used.

## OAuth support

The SQLModel adapter includes full OAuth support. The `OAuthAccountRecord` model is included and the adapter implements all OAuth methods from `AbstractUserAdapter`.
