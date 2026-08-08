# Tortoise ORM Adapter

For projects built on [Tortoise ORM](https://tortoise.github.io/), the async, Django-like ORM.

## Installation

```bash
pip install fastapi-fullauth[tortoise]
```

## How it differs from the SQL adapters

- **No `session_maker`.** Tortoise manages its connections through a global registry, so the adapter takes no session factory - it uses the active connection (or the running transaction's connection).
- **Native many-to-many relations.** Roles and permissions are real Tortoise M2M fields you declare on your `User` / `Role` models, so there is **no** `user_role_model` / `role_permission_model` - Tortoise owns the association tables.
- **App-label convention.** Name your concrete models `User` / `Role` / `Permission` and register them under the Tortoise app label `models` (the default `modules={"models": [...]}`). The mixins' foreign keys and the relations reference them by that label (`"models.User"`, `"models.Role"`, `"models.Permission"`).

## Setup

### 1. Define your tables

Each mixin is an **abstract** Tortoise model. Subclass it and give the subclass its own `Meta` with a `table` name (Tortoise does not inherit an abstract `Meta`). Only subclass the mixins for features you use.

```python
from tortoise import fields
from fastapi_fullauth.models.tortoise import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
)


class Permission(PermissionMixin):
    class Meta:
        table = "fullauth_permissions"


class Role(RoleMixin):
    # opt into permissions: declare the M2M to your Permission model.
    # related_name="roles" is required - the adapter resolves a role's
    # permissions through that reverse accessor.
    permissions = fields.ManyToManyField(
        "models.Permission", related_name="roles", through="fullauth_role_permissions"
    )

    class Meta:
        table = "fullauth_roles"


class RefreshToken(RefreshTokenMixin):
    class Meta:
        table = "fullauth_refresh_tokens"


class OAuthAccount(OAuthAccountMixin):
    class Meta:
        table = "fullauth_oauth_accounts"
        # required: makes concurrent OAuth callbacks for the same identity
        # collapse to one account instead of duplicating.
        unique_together = (("provider", "provider_user_id"),)


class Passkey(PasskeyMixin):
    class Meta:
        table = "fullauth_passkeys"


class User(UserMixin):
    display_name = fields.CharField(max_length=100, default="")
    # opt into roles: declare the M2M to your Role model.
    roles = fields.ManyToManyField(
        "models.Role", related_name="users", through="fullauth_user_roles"
    )

    class Meta:
        table = "fullauth_users"
```

`UserMixin` provides these columns:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUID` (UUID7) | Primary key, auto-generated |
| `email` | `str` | Unique |
| `hashed_password` | `str \| None` | Password hash. `NULL` for OAuth-only users. |
| `is_active` | `bool` | Account active flag |
| `is_verified` | `bool` | Email verified flag |
| `is_superuser` | `bool` | Superuser flag |
| `created_at` | `datetime` | UTC creation timestamp |

A minimal setup needs only `UserMixin` and `RefreshTokenMixin`.

### 2. Create the adapter

```python
from fastapi_fullauth.adapters import TortoiseAdapter

adapter = TortoiseAdapter(
    user_model=User,
    refresh_token_model=RefreshToken,
    role_model=Role,
    permission_model=Permission,
    oauth_account_model=OAuthAccount,
    passkey_model=Passkey,
)
```

Required kwargs: `user_model`, `refresh_token_model`. Optional kwargs (pass the ones for features you use): `role_model`, `permission_model`, `oauth_account_model`, `passkey_model`. Calling a feature method without its model raises `RuntimeError` naming the missing argument. There is no `user_role_model` / `role_permission_model` - those are native M2M relations on your models.

For a multi-database setup, pass `connection_name="..."` to target a non-default Tortoise connection.

### 3. Initialize Tortoise and wire into FullAuth

Initialize Tortoise in your app's lifespan, registering your models under the `models` app label. `init_app()` wraps your lifespan so `fullauth.aclose()` runs on shutdown automatically - you only manage the Tortoise teardown:

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise import Tortoise

from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(adapter=adapter, config=FullAuthConfig(SECRET_KEY="your-secret-key"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await Tortoise.init(
        db_url="sqlite://db.sqlite3",
        modules={"models": ["yourapp.models"]},  # app label MUST be "models"
    )
    await Tortoise.generate_schemas()  # dev only; use migrations in production
    yield
    await Tortoise.close_connections()


app = FastAPI(lifespan=lifespan)
fullauth.init_app(app)
```

## Tables created

Tables are created from the mixins you subclass:

| Group | Tables | Mixins / relations |
|-------|--------|--------------------|
| Core (always) | `fullauth_users`, `fullauth_refresh_tokens` | `UserMixin`, `RefreshTokenMixin` |
| Roles | `fullauth_roles`, `fullauth_user_roles` | `RoleMixin` + `User.roles` M2M |
| Permissions | `fullauth_permissions`, `fullauth_role_permissions` | `PermissionMixin` + `Role.permissions` M2M |
| OAuth | `fullauth_oauth_accounts` | `OAuthAccountMixin` |
| Passkeys | `fullauth_passkeys` | `PasskeyMixin` |

The `fullauth_user_roles` and `fullauth_role_permissions` association tables are created by Tortoise from the M2M fields you declare (via the `through=` names above).

Deleting a user cascades to its refresh tokens, OAuth accounts, passkeys, and role links (the foreign keys use `ON DELETE CASCADE`, and Tortoise enables foreign-key enforcement).

## Custom schemas

Define your own schemas and pass them to the adapter:

```python
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""

class MyCreateSchema(CreateUserSchema):
    display_name: str = ""

adapter = TortoiseAdapter(
    user_model=User,
    refresh_token_model=RefreshToken,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

If your app uses roles, add `roles` to your custom schema so the login response and `/me` expose them:

```python
from pydantic import Field

class MyUserSchema(UserSchema):
    roles: list[str] = Field(default_factory=list)
```

## Migrations

`Tortoise.generate_schemas()` is convenient for prototyping but does not version your schema. For production, use Tortoise's built-in migration CLI (available in tortoise-orm 1.0+):

```bash
python -m tortoise makemigrations
python -m tortoise migrate
```

See the [Tortoise migrations guide](https://github.com/tortoise/tortoise-orm#migrations) for configuring the CLI against your `models` app.

> **Windows note:** tortoise-orm 1.x uses timezone-aware datetimes via `zoneinfo`, which has no bundled timezone database on Windows. Install [`tzdata`](https://pypi.org/project/tzdata/) (`pip install tzdata`) so timestamp columns resolve their UTC zone.
