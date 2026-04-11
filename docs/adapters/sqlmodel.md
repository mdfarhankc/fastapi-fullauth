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
from fastapi_fullauth.adapters.sqlmodel import (
    UserBase, Role, UserRoleLink, RefreshTokenRecord,
)

class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    # add your custom fields
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    # required relationships
    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()
```

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
from fastapi_fullauth import FullAuth

fullauth = FullAuth(
    secret_key="your-secret-key",
    adapter=adapter,
)
```

## Tables created

The SQLModel adapter uses these tables:

| Table | Purpose |
|-------|---------|
| `fullauth_users` | User accounts (your model) |
| `fullauth_roles` | Role definitions |
| `fullauth_user_roles` | User-role link table |
| `fullauth_refresh_tokens` | Stored refresh tokens |
| `fullauth_oauth_accounts` | Linked OAuth provider accounts |

## Custom user schema

By default, the response schema is auto-derived from your model. To use an explicit schema:

```python
from pydantic import BaseModel, EmailStr
from fastapi_fullauth.types import UserSchema

class MyUserResponse(UserSchema):
    display_name: str = ""
    phone: str = ""

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    user_schema=MyUserResponse,
)
```

## OAuth support

The SQLModel adapter includes full OAuth support. The `OAuthAccountRecord` model is included and the adapter implements all OAuth methods from `AbstractUserAdapter`.
