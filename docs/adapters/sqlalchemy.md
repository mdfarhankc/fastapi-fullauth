# SQLAlchemy Adapter

Use this adapter if your project already uses SQLAlchemy's declarative base.

## Installation

```bash
pip install fastapi-fullauth[sqlalchemy]
```

## Setup

### 1. Define your user model

```python
from sqlalchemy import Boolean, Column, DateTime, String, Table, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from fastapi_fullauth.adapters.sqlalchemy.models import (
    FullAuthBase, RoleModel, UserBase, user_role_table,
)

class User(UserBase):
    __tablename__ = "fullauth_users"

    # add your custom fields
    display_name: Mapped[str] = mapped_column(String(100), default="")
    phone: Mapped[str] = mapped_column(String(20), default="")

    # required relationships
    roles: Mapped[list[RoleModel]] = relationship(secondary=user_role_table)
```

`UserBase` provides the same core fields as the SQLModel version: `id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `created_at`.

### 2. Create the adapter

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter

engine = create_async_engine("sqlite+aiosqlite:///app.db")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

adapter = SQLAlchemyAdapter(session_maker=session_maker, user_model=User)
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

## Table creation

Use your existing Alembic setup or create tables directly:

```python
async with engine.begin() as conn:
    await conn.run_sync(FullAuthBase.metadata.create_all)
```

## Schema derivation

The SQLAlchemy adapter auto-derives schemas from your model's column definitions. Column types are mapped to Python types:

| SQLAlchemy Type | Python Type |
|-----------------|-------------|
| `String`, `Text` | `str` |
| `Integer` | `int` |
| `Float`, `Numeric` | `float` |
| `Boolean` | `bool` |
