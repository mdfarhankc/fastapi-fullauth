from typing import TYPE_CHECKING, Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION
from fastapi_fullauth.types import UserSchema, UserSchemaType

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth

# shows the lock icon + "Bearer token" input in Swagger UI
_bearer_scheme = HTTPBearer(auto_error=False)


def _get_fullauth(request: Request) -> "FullAuth":
    # type: ignore[union-attr]
    fullauth: FullAuth | None = request.app.state.fullauth
    if fullauth is None:
        raise RuntimeError("FullAuth not initialized on app.state")
    return fullauth


async def _extract_token(
    request: Request,
    fullauth: "FullAuth" = Depends(_get_fullauth),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    if credentials is not None:
        return credentials.credentials
    # fallback to backends (cookie, etc.)
    for backend in fullauth.backends:
        token = await backend.read_token(request)
        if token is not None:
            return token
    raise CREDENTIALS_EXCEPTION


async def current_user(
    fullauth: "FullAuth" = Depends(_get_fullauth),
    token: str = Depends(_extract_token),
) -> UserSchema:
    from fastapi_fullauth.exceptions import TokenError

    try:
        payload = await fullauth.token_engine.decode_token(token)
    except TokenError:
        raise CREDENTIALS_EXCEPTION

    if payload.type != "access":
        raise CREDENTIALS_EXCEPTION

    if payload.extra.get("purpose"):
        raise CREDENTIALS_EXCEPTION

    user = await fullauth.adapter.get_user_by_id(payload.sub)
    if user is None or not user.is_active:
        raise CREDENTIALS_EXCEPTION

    return user


CurrentUser = Annotated[UserSchema, Depends(current_user)]


async def current_active_verified_user(
    user: CurrentUser,
) -> UserSchema:
    from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION

    if not user.is_verified:
        raise FORBIDDEN_EXCEPTION
    return user


async def current_superuser(
    user: CurrentUser,
) -> UserSchema:
    from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION

    if not user.is_superuser:
        raise FORBIDDEN_EXCEPTION
    return user


VerifiedUser = Annotated[UserSchema, Depends(current_active_verified_user)]
SuperUser = Annotated[UserSchema, Depends(current_superuser)]


def get_current_user_dependency(user_type: type[UserSchemaType]):
    """Create a typed current_user dependency for custom user schemas.

    Usage::

        MyCurrentUser = Annotated[MyUserSchema, Depends(get_current_user_dependency(MyUserSchema))]
    """

    async def _current_user(
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> UserSchemaType:
        from fastapi_fullauth.exceptions import TokenError

        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if payload.type != "access":
            raise CREDENTIALS_EXCEPTION

        if payload.extra.get("purpose"):
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(payload.sub)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        return cast(UserSchemaType, user)

    return _current_user


def get_verified_user_dependency(user_type: type[UserSchemaType]):
    """Create a typed verified-user dependency for custom user schemas."""
    _current = get_current_user_dependency(user_type)

    async def _dep(
        user: UserSchemaType = Depends(_current),
    ) -> UserSchemaType:
        from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION

        if not user.is_verified:
            raise FORBIDDEN_EXCEPTION
        return user

    return _dep


def get_superuser_dependency(user_type: type[UserSchemaType]):
    """Create a typed superuser dependency for custom user schemas."""
    _current = get_current_user_dependency(user_type)

    async def _dep(
        user: UserSchemaType = Depends(_current),
    ) -> UserSchemaType:
        from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION

        if not user.is_superuser:
            raise FORBIDDEN_EXCEPTION
        return user

    return _dep
