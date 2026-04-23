from typing import TYPE_CHECKING

from fastapi import Depends

from fastapi_fullauth.dependencies.current_user import _get_fullauth, current_user
from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION
from fastapi_fullauth.types import UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def require_role(*roles: str):
    """Dependency that checks the user has at least one of the given roles."""

    async def _dep(
        user: UserSchema = Depends(current_user),
    ) -> UserSchema:
        if user.is_superuser:
            return user

        # getattr keeps this usable with a minimal UserSchema that has no
        # roles field — caller gets a clean 403 instead of AttributeError.
        user_roles = set(getattr(user, "roles", []) or [])
        if not user_roles.intersection(roles):
            raise FORBIDDEN_EXCEPTION

        return user

    return _dep


def require_permission(*permissions: str):
    """Dependency that checks the user has at least one of the given permissions.

    Permissions use the format 'resource:action' (e.g. 'posts:delete').
    Resolves permissions through the user's roles.
    """

    async def _dep(
        user: UserSchema = Depends(current_user),
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> UserSchema:
        if user.is_superuser:
            return user

        user_perms = await fullauth.adapter.get_user_permissions(user.id)
        if not set(permissions).intersection(user_perms):
            raise FORBIDDEN_EXCEPTION

        return user

    return _dep
