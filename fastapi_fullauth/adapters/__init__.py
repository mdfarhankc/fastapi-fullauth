from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
)

__all__ = [
    "AbstractUserAdapter",
    "OAuthAdapterMixin",
    "PasskeyAdapterMixin",
    "PermissionAdapterMixin",
    "RoleAdapterMixin",
]

# lazy imports for optional adapters to avoid import errors
# when sqlalchemy/sqlmodel are not installed


def __getattr__(name: str):
    if name == "SQLAlchemyAdapter":
        from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter

        return SQLAlchemyAdapter
    if name == "SQLModelAdapter":
        from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

        return SQLModelAdapter
    raise AttributeError(f"module 'fastapi_fullauth.adapters' has no attribute {name!r}")
