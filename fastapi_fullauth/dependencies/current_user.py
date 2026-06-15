from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION
from fastapi_fullauth.types import TokenPayload, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth

# shows the lock icon + "Bearer token" input in Swagger UI
_bearer_scheme = HTTPBearer(auto_error=False)


def get_fullauth(request: Request) -> "FullAuth":
    fullauth: FullAuth | None = getattr(request.app.state, "fullauth", None)
    if fullauth is None:
        raise RuntimeError("FullAuth not initialized on app.state")
    return fullauth


async def _extract_token(
    request: Request,
    fullauth: "FullAuth" = Depends(get_fullauth),
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


async def current_token_payload(
    fullauth: "FullAuth" = Depends(get_fullauth),
    token: str = Depends(_extract_token),
) -> TokenPayload:
    """Decoded access-token payload for the current request.

    Reads the token from the Authorization header or a cookie backend, validates
    it, and returns the TokenPayload - including any custom claims in ``extra``.
    Use this when you only need claims (no database hit); use ``current_user``
    when you need the user record.
    """
    from fastapi_fullauth.exceptions import TokenError

    try:
        payload = await fullauth.token_engine.decode_token(token, expected_type="access")
    except TokenError:
        raise CREDENTIALS_EXCEPTION

    # A session token must not carry a purpose (password-reset, email-verify,
    # oauth-state tokens are access-typed but purpose-scoped).
    if payload.extra.get("purpose"):
        raise CREDENTIALS_EXCEPTION

    return payload


async def current_user(
    fullauth: "FullAuth" = Depends(get_fullauth),
    payload: TokenPayload = Depends(current_token_payload),
) -> UserSchema:
    try:
        user_id = UUID(payload.sub)
    except ValueError:
        raise CREDENTIALS_EXCEPTION

    user = await fullauth.adapter.get_user_by_id(user_id)
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
