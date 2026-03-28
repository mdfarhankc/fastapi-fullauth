from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer

from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def _get_fullauth(request: Request) -> FullAuth:
    fullauth: FullAuth | None = request.app.state.fullauth  # type: ignore[union-attr]
    if fullauth is None:
        raise RuntimeError("FullAuth not initialized on app.state")
    return fullauth


async def _extract_token(
    request: Request,
    fullauth: FullAuth = Depends(_get_fullauth),
    bearer_token: str | None = Depends(oauth2_scheme),
) -> str:
    # try OAuth2 bearer from Swagger first
    if bearer_token is not None:
        return bearer_token
    # fallback to backends (cookie, etc.)
    for backend in fullauth.backends:
        token = await backend.read_token(request)
        if token is not None:
            return token
    raise CREDENTIALS_EXCEPTION


async def current_user(
    request: Request,
    fullauth: FullAuth = Depends(_get_fullauth),
    token: str = Depends(_extract_token),
):
    from fastapi_fullauth.exceptions import TokenError

    try:
        payload = fullauth.token_engine.decode_token(token)
    except TokenError:
        raise CREDENTIALS_EXCEPTION

    if payload.type != "access":
        raise CREDENTIALS_EXCEPTION

    user = await fullauth.adapter.get_user_by_id(payload.sub)
    if user is None or not user.is_active:
        raise CREDENTIALS_EXCEPTION

    return user


async def current_active_verified_user(
    request: Request,
    fullauth: FullAuth = Depends(_get_fullauth),
    token: str = Depends(_extract_token),
):
    from fastapi_fullauth.exceptions import FORBIDDEN_EXCEPTION, TokenError

    try:
        payload = fullauth.token_engine.decode_token(token)
    except TokenError:
        raise CREDENTIALS_EXCEPTION

    user = await fullauth.adapter.get_user_by_id(payload.sub)
    if user is None or not user.is_active:
        raise CREDENTIALS_EXCEPTION
    if not user.is_verified:
        raise FORBIDDEN_EXCEPTION

    return user
