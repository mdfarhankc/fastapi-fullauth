# Adapters

Adapters are the database layer for fastapi-fullauth. They implement `AbstractUserAdapter`, which defines how users, refresh tokens, roles, and OAuth accounts are stored and retrieved.

## Available adapters

| Adapter | Backend | Install |
|---------|---------|---------|
| [SQLModel](sqlmodel.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlmodel]` |
| [SQLAlchemy](sqlalchemy.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlalchemy]` |
| [In-Memory](memory.md) | Python dicts | Included (no extras) |

## Choosing an adapter

- **SQLModel** — recommended for most projects. Clean model definitions, good type support.
- **SQLAlchemy** — use if your project already uses SQLAlchemy's declarative base.
- **In-Memory** — for testing and prototyping only. Data is lost on restart.

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

## Auto-derived schemas

All adapters support automatic schema derivation. When you add custom fields to your user model, fastapi-fullauth detects them and includes them in:

- **Registration schema** — extra fields appear in `POST /auth/register`
- **User response schema** — extra fields appear in `GET /auth/me` and other user responses

No need to create separate Pydantic models. You can still pass explicit `user_schema` or `create_user_schema` to `SQLModelAdapter` / `FullAuth` if you want full control.
