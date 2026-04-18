"""SQLModel table definitions for fastapi-fullauth.

Import from sub-modules to register only the tables you need:

    # Core only (users + refresh tokens)
    from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord

    # Add roles
    from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink

    # Add permissions (requires roles)
    from fastapi_fullauth.adapters.sqlmodel.models.permission import Permission, RolePermissionLink

    # Add OAuth
    from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord

    # Add Passkeys
    from fastapi_fullauth.adapters.sqlmodel.models.passkey import PasskeyRecord
"""

_LAZY_IMPORTS = {
    "UserBase": "fastapi_fullauth.adapters.sqlmodel.models.base",
    "RefreshTokenRecord": "fastapi_fullauth.adapters.sqlmodel.models.base",
    "Role": "fastapi_fullauth.adapters.sqlmodel.models.role",
    "UserRoleLink": "fastapi_fullauth.adapters.sqlmodel.models.role",
    "Permission": "fastapi_fullauth.adapters.sqlmodel.models.permission",
    "RolePermissionLink": "fastapi_fullauth.adapters.sqlmodel.models.permission",
    "OAuthAccountRecord": "fastapi_fullauth.adapters.sqlmodel.models.oauth",
    "PasskeyRecord": "fastapi_fullauth.adapters.sqlmodel.models.passkey",
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str):
    module_path = _LAZY_IMPORTS.get(name)
    if module_path is not None:
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
