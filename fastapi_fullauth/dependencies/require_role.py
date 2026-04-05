from typing import TYPE_CHECKING

from fastapi import Depends, Request

from fastapi_fullauth.dependencies.current_user import _extract_token, _get_fullauth
from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION, FORBIDDEN_EXCEPTION
from fastapi_fullauth.types import UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def require_role(*roles: str):
    """Dependency that checks the user has at least one of the given roles."""

    async def _dep(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> UserSchema:
        from fastapi_fullauth.exceptions import TokenError

        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(payload.sub)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        if user.is_superuser:
            return user

        user_roles = set(payload.roles)
        if not user_roles.intersection(roles):
            raise FORBIDDEN_EXCEPTION

        return user

    return _dep


def require_permission(*permissions: str):
    """Dependency that checks the user has at least one of the given permissions.

    Permissions use the format 'resource:action' (e.g. 'posts:delete').
    For now, this checks against roles. A full permission engine comes later.
    """

    async def _dep(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> UserSchema:
        from fastapi_fullauth.exceptions import TokenError

        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(payload.sub)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        if user.is_superuser:
            return user

        # TODO: implement full permission resolution against RBAC engine
        # For now, permissions map 1:1 to roles
        user_roles = set(payload.roles)
        if not user_roles.intersection(permissions):
            raise FORBIDDEN_EXCEPTION

        return user

    return _dep
