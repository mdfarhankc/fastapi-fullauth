# SQLAlchemy Adapter

Use this adapter if your project already uses SQLAlchemy's declarative base. Bring your own `DeclarativeBase` — the library doesn't ship one.

## Installation

```bash
pip install fastapi-fullauth[sqlalchemy]
```

## Setup

### 1. Define your tables

Each library table is a **mixin** you combine with your own `DeclarativeBase`. Only subclass the mixins for features you use.

```python
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from fastapi_fullauth.models.sqlalchemy import (
    RefreshTokenMixin, RoleMixin, UserMixin, UserRoleMixin,
)


class Base(DeclarativeBase):
    pass


class RefreshToken(RefreshTokenMixin, Base):
    pass


class Role(RoleMixin, Base):
    pass


class UserRole(UserRoleMixin, Base):
    pass


class User(UserMixin, Base):
    display_name: Mapped[str] = mapped_column(String(100), default="")
    phone: Mapped[str] = mapped_column(String(20), default="")

    roles: Mapped[list[Role]] = relationship(
        secondary="fullauth_user_roles", lazy="selectin",
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")
```

`UserMixin` provides `id`, `email`, `hashed_password` (nullable — `NULL` for OAuth-only users), `is_active`, `is_verified`, `is_superuser`, `created_at`.

### 2. Create the adapter

Pass each concrete model class you defined — required for the features you use:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from fastapi_fullauth.adapters import SQLAlchemyAdapter

engine = create_async_engine("sqlite+aiosqlite:///app.db")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

adapter = SQLAlchemyAdapter(
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

## Table creation

Use your existing Alembic setup or create tables directly off your own `Base`:

```python
async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)
```

## Custom schemas

Define your own schemas and pass them to the adapter:

```python
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""

class MyCreateSchema(CreateUserSchema):
    display_name: str

adapter = SQLAlchemyAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

If you don't pass custom schemas, the base `UserSchema` and `CreateUserSchema` are used.
