# Adapters

Adapters are the database layer for fastapi-fullauth. They implement `AbstractUserAdapter`, which defines how users, refresh tokens, roles, and OAuth accounts are stored and retrieved.

## Available adapters

| Adapter | Backend | Install |
|---------|---------|---------|
| [SQLModel](sqlmodel.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlmodel]` |
| [SQLAlchemy](sqlalchemy.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlalchemy]` |

## Choosing an adapter

- **SQLModel** — recommended for most projects. Clean model definitions, good type support. Use SQLite for prototyping.
- **SQLAlchemy** — use if your project already uses SQLAlchemy's declarative base.

## Custom adapters

You can implement your own adapter for any database by subclassing `AbstractUserAdapter`:

```python
from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserSchema

class MongoAdapter(AbstractUserAdapter):
    async def get_user_by_id(self, user_id: str) -> UserSchema | None:
        ...

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        ...

    async def create_user(self, data: CreateUserSchema, hashed_password: str) -> UserSchema:
        ...

    # ... implement all abstract methods
```

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
    session_maker=session_maker,
    user_model=User,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```
