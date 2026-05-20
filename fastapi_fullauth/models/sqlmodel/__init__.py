"""SQLModel mixins for fastapi-fullauth.

Combine each mixin with ``table=True`` to register only the tables you need.

    # Core (users + refresh tokens)
    from fastapi_fullauth.models.sqlmodel import UserMixin, RefreshTokenMixin

    # Roles
    from fastapi_fullauth.models.sqlmodel import RoleMixin, UserRoleMixin

    # Permissions (requires roles)
    from fastapi_fullauth.models.sqlmodel import PermissionMixin, RolePermissionMixin

    # OAuth
    from fastapi_fullauth.models.sqlmodel import OAuthAccountMixin

    # Passkeys
    from fastapi_fullauth.models.sqlmodel import PasskeyMixin

Mixins are only re-exported when ``sqlmodel`` is installed = a missing
extra leaves them unbound rather than breaking import.
"""

__all__: list[str] = []

try:
    import sqlmodel  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.models.sqlmodel.base import (
        RefreshTokenMixin,
        UserMixin,
    )
    from fastapi_fullauth.models.sqlmodel.oauth import OAuthAccountMixin
    from fastapi_fullauth.models.sqlmodel.passkey import PasskeyMixin
    from fastapi_fullauth.models.sqlmodel.permission import (
        PermissionMixin,
        RolePermissionMixin,
    )
    from fastapi_fullauth.models.sqlmodel.role import (
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
