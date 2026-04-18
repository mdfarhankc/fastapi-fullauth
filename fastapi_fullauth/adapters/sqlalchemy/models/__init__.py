"""SQLAlchemy table definitions for fastapi-fullauth.

Import from sub-modules to register only the tables you need:

    # Core only (users + refresh tokens)
    from fastapi_fullauth.adapters.sqlalchemy.models.base import (
        FullAuthBase, UserBase, RefreshTokenModel,
    )

    # Add roles
    from fastapi_fullauth.adapters.sqlalchemy.models.role import (
        RoleModel, UserRoleModel,
    )

    # Add permissions (requires roles)
    from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
        PermissionModel, RolePermissionModel,
    )

    # Add OAuth
    from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

    # Add Passkeys
    from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel
"""

_LAZY_IMPORTS = {
    "FullAuthBase": "fastapi_fullauth.adapters.sqlalchemy.models.base",
    "UserBase": "fastapi_fullauth.adapters.sqlalchemy.models.base",
    "RefreshTokenModel": "fastapi_fullauth.adapters.sqlalchemy.models.base",
    "RoleModel": "fastapi_fullauth.adapters.sqlalchemy.models.role",
    "UserRoleModel": "fastapi_fullauth.adapters.sqlalchemy.models.role",
    "PermissionModel": "fastapi_fullauth.adapters.sqlalchemy.models.permission",
    "RolePermissionModel": "fastapi_fullauth.adapters.sqlalchemy.models.permission",
    "OAuthAccountModel": "fastapi_fullauth.adapters.sqlalchemy.models.oauth",
    "PasskeyModel": "fastapi_fullauth.adapters.sqlalchemy.models.passkey",
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str):
    module_path = _LAZY_IMPORTS.get(name)
    if module_path is not None:
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
