"""SQLAlchemy mixins for fastapi-fullauth.

Combine each mixin with your own ``DeclarativeBase`` to register only the
tables you need.

    # Core (users + refresh tokens)
    from fastapi_fullauth.models.sqlalchemy import UserMixin, RefreshTokenMixin

    # Roles
    from fastapi_fullauth.models.sqlalchemy import RoleMixin, UserRoleMixin

    # Permissions (requires roles)
    from fastapi_fullauth.models.sqlalchemy import PermissionMixin, RolePermissionMixin

    # OAuth
    from fastapi_fullauth.models.sqlalchemy import OAuthAccountMixin

    # Passkeys
    from fastapi_fullauth.models.sqlalchemy import PasskeyMixin

Mixins are only re-exported when ``sqlalchemy`` is installed = a missing
extra leaves them unbound rather than breaking import.
"""

__all__: list[str] = []

try:
    import sqlalchemy  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.models.sqlalchemy.base import (
        RefreshTokenMixin,
        UserMixin,
    )
    from fastapi_fullauth.models.sqlalchemy.oauth import OAuthAccountMixin
    from fastapi_fullauth.models.sqlalchemy.passkey import PasskeyMixin
    from fastapi_fullauth.models.sqlalchemy.permission import (
        PermissionMixin,
        RolePermissionMixin,
    )
    from fastapi_fullauth.models.sqlalchemy.role import (
        RoleMixin,
        UserRoleMixin,
    )

    __all__ += [
        "OAuthAccountMixin",
        "PasskeyMixin",
        "PermissionMixin",
        "RefreshTokenMixin",
        "RoleMixin",
        "RolePermissionMixin",
        "UserMixin",
        "UserRoleMixin",
    ]
