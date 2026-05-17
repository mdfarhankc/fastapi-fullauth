# Database Migrations

The library doesn't own your metadata registry. Your `models/` package owns every concrete table you subclass from a `*Mixin`, and your own `Base.metadata` (SQLAlchemy) or `SQLModel.metadata` is the single source of truth for Alembic.

## Quick start (without Alembic)

For development or simple projects, create tables directly off your own Base:

=== "SQLModel"

    ```python
    from sqlmodel import SQLModel

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    ```

=== "SQLAlchemy"

    ```python
    from app.core.db import Base   # your DeclarativeBase

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    ```

## Alembic integration

For production, use Alembic for proper migration management.

### 1. Initialize Alembic

```bash
alembic init alembic
```

### 2. Update env.py

Import your `models` package so every concrete table you defined registers on `Base.metadata`, then point Alembic at that metadata.

=== "SQLModel"

    ```python
    # alembic/env.py
    import app.models  # noqa: F401 — registers all your concrete tables
    from sqlmodel import SQLModel

    target_metadata = SQLModel.metadata
    ```

=== "SQLAlchemy"

    ```python
    # alembic/env.py
    import app.models  # noqa: F401
    from app.core.db import Base

    target_metadata = Base.metadata
    ```

### 3. Generate migrations

```bash
alembic revision --autogenerate -m "add fullauth tables"
alembic upgrade head
```

## Opt-in tables

Each library table is a mixin that registers only when you subclass it. Subclass only the features you actually use:

| Feature | Tables | Mixins to subclass |
|---------|--------|--------------------|
| Core | `fullauth_users`, `fullauth_refresh_tokens` | `UserMixin`, `RefreshTokenMixin` |
| Roles | `fullauth_roles`, `fullauth_user_roles` | `RoleMixin`, `UserRoleMixin` |
| Permissions | `fullauth_permissions`, `fullauth_role_permissions` | `PermissionMixin`, `RolePermissionMixin` |
| OAuth | `fullauth_oauth_accounts` | `OAuthAccountMixin` |
| Passkeys | `fullauth_passkeys` | `PasskeyMixin` |

When you turn on a new feature later, add the concrete class, re-run autogenerate, and you get a clean `CREATE TABLE` migration for just that table.
