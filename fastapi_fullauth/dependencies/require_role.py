from fastapi import Depends

from fastapi_fullauth.dependencies.current_user import current_user
from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION
from fastapi_fullauth.types import UserSchema


def require_role(*roles: str):
    """Dependency that checks the user has at least one of the given roles."""

    async def _dep(
        user: UserSchema = Depends(current_user),
    ) -> UserSchema:
        if user.is_superuser:
            return user

        user_roles = set(user.roles)
        if not user_roles.intersection(roles):
            raise FORBIDDEN_EXCEPTION

        return user

    return _dep


def require_permission(*permissions: str):
    """Dependency that checks the user has at least one of the given permissions.

    Permissions use the format 'resource:action' (e.g. 'posts:delete').
    When a full permission engine is added, this will resolve permissions
    against it. For now, permissions map 1:1 to roles.
    """
    return require_role(*permissions)
