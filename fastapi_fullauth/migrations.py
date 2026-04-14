"""Alembic integration helpers for fastapi-fullauth.

Usage in your alembic env.py:

    # For SQLAlchemy adapter (all tables):
    from fastapi_fullauth.migrations import include_fullauth_models
    from your_app.models import Base  # your app's declarative base

    include_fullauth_models("sqlalchemy")
    target_metadata = Base.metadata

    # Selective — only core + roles (no permissions/oauth tables):
    include_fullauth_models("sqlmodel", include=["base", "role"])

    # For SQLModel adapter:
    include_fullauth_models("sqlmodel")
    from sqlmodel import SQLModel
    target_metadata = SQLModel.metadata
"""

from typing import Literal

from sqlalchemy import MetaData

AdapterType = Literal["sqlalchemy", "sqlmodel"]
ModelGroup = Literal["base", "role", "permission", "oauth"]

_ALL_MODEL_GROUPS: list[ModelGroup] = ["base", "role", "permission", "oauth"]

_SQLMODEL_IMPORTS: dict[ModelGroup, str] = {
    "base": "fastapi_fullauth.adapters.sqlmodel.models.base",
    "role": "fastapi_fullauth.adapters.sqlmodel.models.role",
    "permission": "fastapi_fullauth.adapters.sqlmodel.models.permission",
    "oauth": "fastapi_fullauth.adapters.sqlmodel.models.oauth",
}

_SQLALCHEMY_IMPORTS: dict[ModelGroup, str] = {
    "base": "fastapi_fullauth.adapters.sqlalchemy.models.base",
    "role": "fastapi_fullauth.adapters.sqlalchemy.models.role",
    "permission": "fastapi_fullauth.adapters.sqlalchemy.models.permission",
    "oauth": "fastapi_fullauth.adapters.sqlalchemy.models.oauth",
}


def include_fullauth_models(
    adapter: AdapterType = "sqlalchemy",
    include: list[ModelGroup] | None = None,
) -> None:
    """Import fullauth models so Alembic detects them for autogenerate.

    Call this in your env.py before setting target_metadata.

    Args:
        adapter: "sqlalchemy" or "sqlmodel"
        include: Model groups to import. Defaults to all.
            Available groups: "base", "role", "permission", "oauth".
            "base" includes users and refresh tokens (always needed).
    """
    import importlib

    groups = include or _ALL_MODEL_GROUPS

    if adapter == "sqlalchemy":
        registry = _SQLALCHEMY_IMPORTS
    elif adapter == "sqlmodel":
        registry = _SQLMODEL_IMPORTS
    else:
        raise ValueError(f"Unknown adapter: {adapter}. Use 'sqlalchemy' or 'sqlmodel'.")

    for group in groups:
        if group not in registry:
            raise ValueError(
                f"Unknown model group: {group}. Valid groups: {', '.join(_ALL_MODEL_GROUPS)}"
            )
        importlib.import_module(registry[group])


def get_fullauth_metadata(adapter: AdapterType = "sqlalchemy") -> MetaData:
    """Get the MetaData object containing fullauth table definitions.

    Useful if you want to combine with your own app's metadata.

    Args:
        adapter: "sqlalchemy" or "sqlmodel"

    Returns:
        SQLAlchemy MetaData containing fullauth tables.
    """
    if adapter == "sqlalchemy":
        from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase

        return FullAuthBase.metadata
    elif adapter == "sqlmodel":
        include_fullauth_models("sqlmodel")
        from sqlmodel import SQLModel

        return SQLModel.metadata
    else:
        raise ValueError(f"Unknown adapter: {adapter}. Use 'sqlalchemy' or 'sqlmodel'.")
