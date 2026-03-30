from __future__ import annotations

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenError, UserNotFoundError
from fastapi_fullauth.types import UserSchema


async def request_password_reset(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    email: str,
) -> str | None:
    """Generate a password reset token. Returns None if user not found (to prevent enumeration)."""
    user = await adapter.get_user_by_email(email)
    if user is None:
        return None

    token = token_engine.create_access_token(
        user_id=str(user.id),
        extra={"purpose": "password_reset"},
    )
    return token


async def reset_password(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    token: str,
    new_password: str,
) -> UserSchema | None:
    payload = token_engine.decode_token(token)

    if payload.extra.get("purpose") != "password_reset":
        raise TokenError("Invalid password reset token")

    user = await adapter.get_user_by_id(payload.sub)
    if user is None:
        raise UserNotFoundError("User not found")

    hashed = hash_password(new_password)
    await adapter.set_password(str(user.id), hashed)

    # Blacklist the reset token so it can't be reused
    token_engine.blacklist_token(payload.jti)

    return user
