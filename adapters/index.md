# Adapters

## What is an adapter

Adapters decouple the authentication logic from the database. The library defines abstract interfaces for user management, token storage, roles, OAuth, and passkeys. Concrete adapters implement these interfaces for specific ORMs.

The library ships adapters for SQLModel, SQLAlchemy, Tortoise ORM, and Beanie (MongoDB). You can write your own for any other data store by implementing the abstract interface.

## Available adapters

| Adapter                                                                                  | Backend                     | Install                                    |
| ---------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------ |
| [SQLModel](https://mdfarhankc.github.io/fastapi-fullauth/adapters/sqlmodel/index.md)     | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlmodel]`   |
| [SQLAlchemy](https://mdfarhankc.github.io/fastapi-fullauth/adapters/sqlalchemy/index.md) | Any SQLAlchemy-supported DB | `pip install fastapi-fullauth[sqlalchemy]` |
| [Tortoise ORM](https://mdfarhankc.github.io/fastapi-fullauth/adapters/tortoise/index.md) | Any Tortoise-supported DB   | `pip install fastapi-fullauth[tortoise]`   |
| [Beanie](https://mdfarhankc.github.io/fastapi-fullauth/adapters/beanie/index.md)         | MongoDB                     | `pip install fastapi-fullauth[beanie]`     |

## Choosing an adapter

- **SQLModel**: recommended for most projects. Clean model definitions, good type support. Use SQLite for prototyping.
- **SQLAlchemy**: use if your project already uses SQLAlchemy's declarative base.
- **Tortoise ORM**: use if your project is built on Tortoise's async, Django-like ORM.
- **Beanie**: use if your data lives in MongoDB. Roles and permissions are embedded on the document rather than joined, and refresh-token rotation stays atomic without a replica set.

All four adapters support the same features. The difference is in model definition style and the data store they bind to.

## Adapter architecture

### Core interface

`AbstractUserAdapter` defines the contract every adapter must implement:

- **User CRUD**: `get_user_by_id()`, `get_user_by_email()`, `get_user_by_field()`, `create_user()`, `update_user()`, `delete_user()`
- **Passwords**: `get_hashed_password()`, `set_password()`
- **Refresh tokens**: `store_refresh_token()`, `get_refresh_token()`, `revoke_refresh_token()`, `revoke_refresh_token_family()`, `revoke_all_user_refresh_tokens()`
- **Verification**: `set_user_verified()`, `get_user_roles()`

### Optional mixins

Mixins add capabilities to your adapter. The library checks `isinstance()` at startup to decide which routers to mount. If your adapter doesn't inherit a mixin, the corresponding feature is simply not available - no dead endpoints, no errors.

| Mixin                    | Enables                        | Required model                           |
| ------------------------ | ------------------------------ | ---------------------------------------- |
| `RoleAdapterMixin`       | Admin router, `require_role()` | `RoleMixin`                              |
| `PermissionAdapterMixin` | `require_permission()`         | `PermissionMixin`, `RolePermissionMixin` |
| `OAuthAdapterMixin`      | OAuth router                   | `OAuthAccountMixin`                      |
| `PasskeyAdapterMixin`    | Passkey router                 | `PasskeyMixin`                           |

## Model mixins

The library provides SQLAlchemy and SQLModel mixins for database tables. You subclass them to create concrete tables in your app's metadata. The library never ships its own tables - your app owns every table definition, which means Alembic migrations work naturally. (Tortoise ships an equivalent set of abstract model mixins with a slightly different shape - native M2M relations, no association tables; see the [Tortoise adapter](https://mdfarhankc.github.io/fastapi-fullauth/adapters/tortoise/index.md).)

| Mixin                 | Default table name          | Purpose                  |
| --------------------- | --------------------------- | ------------------------ |
| `UserMixin`           | `fullauth_users`            | User accounts            |
| `RefreshTokenMixin`   | `fullauth_refresh_tokens`   | Stored refresh tokens    |
| `RoleMixin`           | `fullauth_roles`            | Role definitions         |
| `UserRoleMixin`       | `fullauth_user_roles`       | User-role assignments    |
| `OAuthAccountMixin`   | `fullauth_oauth_accounts`   | Linked OAuth providers   |
| `PasskeyMixin`        | `fullauth_passkeys`         | WebAuthn credentials     |
| `PermissionMixin`     | `fullauth_permissions`      | Permission definitions   |
| `RolePermissionMixin` | `fullauth_role_permissions` | Role-permission mappings |

You only need the mixins for features you use. A minimal setup needs just `UserMixin` and `RefreshTokenMixin`.

## Custom adapters

Not using SQL? Subclass `AbstractUserAdapter` for core auth and add a mixin per feature you need. The library checks `isinstance()` at startup, so routers for unimplemented features never mount.

See **[Writing a custom adapter](https://mdfarhankc.github.io/fastapi-fullauth/adapters/custom/index.md)** for a complete, runnable worked example (an in-memory store), the key method contracts, and how to opt into roles, permissions, OAuth, passkeys, and sessions.

## Custom schemas

Define your own user schemas by extending `UserSchema` and `CreateUserSchema`, then pass them to the adapter:

```
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""

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

The `UserSchema` base class defines `PROTECTED_FIELDS` - a set of fields that can't be updated via `PATCH /me`. By default this includes `id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, `roles`, `password`, `created_at`, and `refresh_tokens`. If your custom schema adds fields that should also be protected from profile updates, extend this set.

If your app uses roles, add `roles` to your custom schema:

```
class MyUserSchema(UserSchema):
    roles: list[str] = Field(default_factory=list)
```

## Choosing a primary key type

User ids are UUIDs by default. Integer, sequence, and string keys take two steps: declare the key type on the schema, and use the same type in your user model and every model that references a user.

### 1. Parameterise the schema

```
class MyUserSchema(UserSchema[int]):   # integer or sequence keys
    display_name: str = ""

class MyUserSchema(UserSchema[str]):   # string keys
    display_name: str = ""
```

The adapter reads the key type off the schema and converts token subjects back to it, so login, refresh, sessions, verification, password reset, and the admin role endpoints work unchanged. `class MyUserSchema(UserSchema)` keeps UUID keys, so existing projects need no edits.

### 2. Match the key type in your models

The bundled mixins use UUID keys. Override `id` on the user model, and `user_id` on each model that references a user: refresh tokens always, plus user roles, OAuth accounts, and passkeys when you use them. The mixins annotate these fields as `UUID`, so type checkers flag the override; the `# type: ignore[assignment]` comments below silence exactly that.

**SQLAlchemy**

```
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

class User(UserMixin, Base):
    id: Mapped[int] = mapped_column(primary_key=True)  # type: ignore[assignment]

class RefreshToken(RefreshTokenMixin, Base):
    user_id: Mapped[int] = mapped_column(  # type: ignore[assignment]
        ForeignKey("fullauth_users.id", ondelete="CASCADE"), index=True
    )

class UserRole(UserRoleMixin, Base):
    user_id: Mapped[int] = mapped_column(  # type: ignore[assignment]
        ForeignKey("fullauth_users.id", ondelete="CASCADE"), primary_key=True
    )

# OAuthAccount and Passkey: same user_id override as RefreshToken
```

**SQLModel**

```
from sqlmodel import Field

class User(UserMixin, table=True):
    id: int | None = Field(default=None, primary_key=True)  # type: ignore[assignment]

class RefreshToken(RefreshTokenMixin, table=True):
    user_id: int = Field(  # type: ignore[assignment]
        foreign_key="fullauth_users.id", ondelete="CASCADE", index=True
    )

class UserRole(UserRoleMixin, table=True):
    user_id: int = Field(  # type: ignore[assignment]
        foreign_key="fullauth_users.id", ondelete="CASCADE", primary_key=True
    )

# OAuthAccount and Passkey: same user_id override as RefreshToken
```

**Tortoise**

```
from tortoise import fields

class User(UserMixin):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "fullauth_users"
```

Only the user model changes. Tortoise derives each foreign key's column type from the model it points at, so the related mixins follow automatically.

**Beanie**

```
from bson import ObjectId
from pydantic import Field

class User(UserDocument):
    id: str = Field(default_factory=lambda: str(ObjectId()))  # type: ignore[assignment]

class RefreshToken(RefreshTokenDocument):
    user_id: str  # type: ignore[assignment]

# OAuthAccount and Passkey: same user_id override as RefreshToken
```

MongoDB does not generate integer or string keys for you, so give `id` a `default_factory`.

The passkey table must keep its UUID primary key, because the library generates passkey ids itself. The primary keys of the other tables (refresh tokens, OAuth accounts, roles) are never read or set by the library, so they can be any type.

### Mismatches fail at startup

The schema, the user model, and the related models have to agree. When they don't, the adapter raises at construction instead of letting every request fail as a confusing 401, or letting a forgotten override slip through SQLite and break inserts on PostgreSQL:

```
User id type mismatch: the user schema (MyUserSchema) declares id: int,
but the user model (User) stores UUID.

User id type mismatch: RefreshToken.user_id stores UUID, but user ids are int.
```

Warning

Sequential integer keys are guessable, so anywhere you expose a user id becomes enumerable. UUIDv7 keys avoid that while staying index-friendly. Prefer integers when an existing schema requires them, not by default.
