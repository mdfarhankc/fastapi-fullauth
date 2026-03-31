from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.adapters.memory import InMemoryAdapter

__all__ = ["AbstractUserAdapter", "InMemoryAdapter"]

# lazy imports for optional adapters to avoid import errors
# when sqlalchemy/sqlmodel are not installed


def __getattr__(name: str):
    if name == "SQLAlchemyAdapter":
        from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter

        return SQLAlchemyAdapter
    if name in ("FullAuthBase", "UserModel", "RoleModel"):
        from fastapi_fullauth.adapters import sqlalchemy as sa

        return getattr(sa, name)
    if name == "SQLModelAdapter":
        from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

        return SQLModelAdapter
    if name in ("User", "Role", "UserBase"):
        from fastapi_fullauth.adapters import sqlmodel as sm

        return getattr(sm, name)
    raise AttributeError(f"module 'fastapi_fullauth.adapters' has no attribute {name!r}")
