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

Subclass `AbstractUserAdapter` for core auth. Add mixins for roles, permissions, or OAuth:

```python
from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
)

# Minimal — just auth
class MyAdapter(AbstractUserAdapter):
    async def get_user_by_id(self, user_id): ...
    async def get_user_by_email(self, email): ...
    async def create_user(self, data, hashed_password): ...
    # ... core methods only

# With roles and permissions
class MyFullAdapter(AbstractUserAdapter, RoleAdapterMixin, PermissionAdapterMixin):
    # ... core + role + permission methods
    pass
```

| Mixin | Methods | When to use |
|-------|---------|-------------|
| `RoleAdapterMixin` | `assign_role`, `remove_role`, `get_user_roles` | Role management |
| `PermissionAdapterMixin` | `get_role_permissions`, `assign_permission_to_role`, `remove_permission_from_role` | RBAC permissions |
| `OAuthAdapterMixin` | `get_oauth_account`, `create_oauth_account`, `update_oauth_account`, `delete_oauth_account`, `get_user_oauth_accounts` | OAuth providers |

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

If your app uses roles, add `roles` to your custom schema:

```python
class MyUserSchema(UserSchema):
    roles: list[str] = Field(default_factory=list)
```
