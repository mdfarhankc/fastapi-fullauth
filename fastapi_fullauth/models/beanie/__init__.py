"""Beanie (MongoDB) document classes for fastapi-fullauth.

Each class is a ready-to-use Beanie ``Document``. Use it directly or subclass it
to add your own fields:

    # Core (users + refresh tokens)
    from fastapi_fullauth.models.beanie import UserDocument, RefreshTokenDocument

    class User(UserDocument):
        display_name: str = ""

    # Roles (membership embedded on the user document)
    from fastapi_fullauth.models.beanie import RoleDocument

    # Permissions (catalog; grants embedded on the role document)
    from fastapi_fullauth.models.beanie import PermissionDocument

    # OAuth / Passkeys
    from fastapi_fullauth.models.beanie import OAuthAccountDocument, PasskeyDocument

Register every document you use with Beanie at startup:
``await init_beanie(database=db, document_models=[User, RefreshToken, ...])``.

Documents are only re-exported when ``beanie`` is installed - a missing extra
leaves them unbound rather than breaking import.
"""

__all__: list[str] = []

try:
    import beanie  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.models.beanie.base import (
        RefreshTokenDocument,
        UserDocument,
    )
    from fastapi_fullauth.models.beanie.oauth import OAuthAccountDocument
    from fastapi_fullauth.models.beanie.passkey import PasskeyDocument
    from fastapi_fullauth.models.beanie.permission import PermissionDocument
    from fastapi_fullauth.models.beanie.role import RoleDocument

    __all__ += [
        "OAuthAccountDocument",
        "PasskeyDocument",
        "PermissionDocument",
        "RefreshTokenDocument",
        "RoleDocument",
        "UserDocument",
    ]
