"""SQLAlchemy table definitions for fastapi-fullauth.

Importing this module registers ALL tables. For selective table creation,
import from sub-modules directly:

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
    from fastapi_fullauth.adapters.sqlalchemy.models.oauth import (
        OAuthAccountModel,
    )
"""

from fastapi_fullauth.adapters.sqlalchemy.models.base import (
    FullAuthBase,
    RefreshTokenModel,
    UserBase,
)
from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel
from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
    PermissionModel,
    RolePermissionModel,
)
from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel, UserRoleModel

__all__ = [
    "FullAuthBase",
    "OAuthAccountModel",
    "PermissionModel",
    "RefreshTokenModel",
    "RoleModel",
    "RolePermissionModel",
    "UserBase",
    "UserRoleModel",
]
