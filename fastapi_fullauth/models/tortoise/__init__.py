"""Tortoise ORM mixins for fastapi-fullauth.

Each mixin is an abstract Tortoise model. Subclass it with a concrete ``Meta``
to register only the tables you need.

    # Core (users + refresh tokens)
    from fastapi_fullauth.models.tortoise import UserMixin, RefreshTokenMixin

    # Roles
    from fastapi_fullauth.models.tortoise import RoleMixin

    # Permissions (requires roles)
    from fastapi_fullauth.models.tortoise import PermissionMixin

    # OAuth
    from fastapi_fullauth.models.tortoise import OAuthAccountMixin

    # Passkeys
    from fastapi_fullauth.models.tortoise import PasskeyMixin

Name your concrete classes ``User`` / ``Role`` / ``Permission`` and register
them under the Tortoise app label ``models`` (``modules={"models": [...]}``):
foreign keys and relations reference them by that label. Roles and permissions
use native Tortoise many-to-many relations you declare on ``User`` / ``Role``
(see each mixin's docstring), so there is no separate association mixin.

Mixins are only re-exported when ``tortoise-orm`` is installed = a missing extra
leaves them unbound rather than breaking import.
"""

__all__: list[str] = []

try:
    import tortoise  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.models.tortoise.base import (
        RefreshTokenMixin,
        UserMixin,
    )
    from fastapi_fullauth.models.tortoise.oauth import OAuthAccountMixin
    from fastapi_fullauth.models.tortoise.passkey import PasskeyMixin
    from fastapi_fullauth.models.tortoise.permission import PermissionMixin
    from fastapi_fullauth.models.tortoise.role import RoleMixin

    __all__ += [
        "OAuthAccountMixin",
        "PasskeyMixin",
        "PermissionMixin",
        "RefreshTokenMixin",
        "RoleMixin",
        "UserMixin",
    ]
