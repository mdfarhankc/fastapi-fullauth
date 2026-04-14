"""SQLModel table definitions for fastapi-fullauth.

Importing this module registers ALL tables. For selective table creation,
import from sub-modules directly:

    # Core only (users + refresh tokens)
    from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase, RefreshTokenRecord

    # Add roles
    from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink

    # Add permissions (requires roles)
    from fastapi_fullauth.adapters.sqlmodel.models.permission import Permission, RolePermissionLink

    # Add OAuth
    from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord
"""

from fastapi_fullauth.adapters.sqlmodel.models.base import RefreshTokenRecord, UserBase
from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord
from fastapi_fullauth.adapters.sqlmodel.models.permission import Permission, RolePermissionLink
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink

__all__ = [
    "OAuthAccountRecord",
    "Permission",
    "RefreshTokenRecord",
    "Role",
    "RolePermissionLink",
    "UserBase",
    "UserRoleLink",
]
