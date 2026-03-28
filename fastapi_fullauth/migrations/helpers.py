"""Alembic integration helpers for fastapi-fullauth.

Usage in your alembic env.py:

    # For SQLAlchemy adapter:
    from fastapi_fullauth.migrations import include_fullauth_models
    from your_app.models import Base  # your app's declarative base

    include_fullauth_models("sqlalchemy")
    target_metadata = Base.metadata  # if using same base
    # OR
    from fastapi_fullauth.migrations import get_fullauth_metadata
    target_metadata = get_fullauth_metadata("sqlalchemy")

    # For SQLModel adapter:
    include_fullauth_models("sqlmodel")
    from sqlmodel import SQLModel
    target_metadata = SQLModel.metadata
"""

from __future__ import annotations

from sqlalchemy import MetaData


def include_fullauth_models(adapter: str = "sqlalchemy") -> None:
    """Import fullauth models so Alembic detects them for autogenerate.

    Call this in your env.py before setting target_metadata.

    Args:
        adapter: "sqlalchemy" or "sqlmodel"
    """
    if adapter == "sqlalchemy":
        import fastapi_fullauth.adapters.sqlalchemy.models  # noqa: F401
    elif adapter == "sqlmodel":
        import fastapi_fullauth.adapters.sqlmodel.models  # noqa: F401
    else:
        raise ValueError(f"Unknown adapter: {adapter}. Use 'sqlalchemy' or 'sqlmodel'.")


def get_fullauth_metadata(adapter: str = "sqlalchemy") -> MetaData:
    """Get the MetaData object containing fullauth table definitions.

    Useful if you want to combine with your own app's metadata.

    Args:
        adapter: "sqlalchemy" or "sqlmodel"

    Returns:
        SQLAlchemy MetaData containing fullauth tables.
    """
    if adapter == "sqlalchemy":
        from fastapi_fullauth.adapters.sqlalchemy.models import FullAuthBase

        return FullAuthBase.metadata
    elif adapter == "sqlmodel":
        include_fullauth_models("sqlmodel")
        from sqlmodel import SQLModel

        return SQLModel.metadata
    else:
        raise ValueError(f"Unknown adapter: {adapter}. Use 'sqlalchemy' or 'sqlmodel'.")
