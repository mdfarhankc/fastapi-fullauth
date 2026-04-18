# Database Migrations

fastapi-fullauth provides Alembic integration helpers for managing database schema migrations.

## Quick start (without Alembic)

For development or simple projects, create tables directly:

=== "SQLModel"

    ```python
    from sqlmodel import SQLModel

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    ```

=== "SQLAlchemy"

    ```python
    from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase

    async with engine.begin() as conn:
        await conn.run_sync(FullAuthBase.metadata.create_all)
    ```

## Alembic integration

For production, use Alembic for proper migration management.

### 1. Initialize Alembic

```bash
alembic init alembic
```

### 2. Update env.py

Import fullauth models so Alembic detects them during autogenerate:

=== "All tables"

    ```python
    # alembic/env.py
    from fastapi_fullauth.migrations import include_fullauth_models
    from sqlmodel import SQLModel

    include_fullauth_models("sqlmodel")

    # import your app's models too
    from your_app.models import User  # noqa: F401

    target_metadata = SQLModel.metadata
    ```

=== "Selective tables"

    ```python
    # alembic/env.py — only core + roles, no permissions/oauth
    from fastapi_fullauth.migrations import include_fullauth_models
    from sqlmodel import SQLModel

    include_fullauth_models("sqlmodel", include=["base", "role"])

    from your_app.models import User  # noqa: F401

    target_metadata = SQLModel.metadata
    ```

=== "SQLAlchemy"

    ```python
    # alembic/env.py
    from fastapi_fullauth.migrations import include_fullauth_models
    from your_app.models import Base  # your declarative base

    include_fullauth_models("sqlalchemy")
    target_metadata = Base.metadata
    ```

### 3. Generate migrations

```bash
alembic revision --autogenerate -m "add fullauth tables"
alembic upgrade head
```

## Model groups

Models are split into groups. Import only what you need:

| Group | Tables | When to include |
|-------|--------|-----------------|
| `base` | `fullauth_users`, `fullauth_refresh_tokens` | Always (core auth) |
| `role` | `fullauth_roles`, `fullauth_user_roles` | When using roles |
| `permission` | `fullauth_permissions`, `fullauth_role_permissions` | When using RBAC permissions |
| `oauth` | `fullauth_oauth_accounts` | When using OAuth providers |
| `passkey` | `fullauth_passkeys` | When using passkey/WebAuthn authentication |

## Helper functions

### `include_fullauth_models(adapter, include=None)`

Imports fullauth model classes so Alembic's autogenerate detects them. Call this in `env.py` before setting `target_metadata`.

```python
from fastapi_fullauth.migrations import include_fullauth_models

# all tables
include_fullauth_models("sqlmodel")

# selective — only core + roles
include_fullauth_models("sqlmodel", include=["base", "role"])
```

### `get_fullauth_metadata(adapter)`

Returns the SQLAlchemy `MetaData` object containing fullauth table definitions. Useful if you need to merge metadata from multiple sources.

```python
from fastapi_fullauth.migrations import get_fullauth_metadata
metadata = get_fullauth_metadata("sqlalchemy")
```
