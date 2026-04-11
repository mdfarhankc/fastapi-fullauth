import logging

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenError, UserNotFoundError
from fastapi_fullauth.types import UserSchema

logger = logging.getLogger("fastapi_fullauth.password_reset")


async def request_password_reset(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    email: str,
) -> str | None:
    """Generate a password reset token. Returns None if user not found (to prevent enumeration)."""
    user = await adapter.get_user_by_email(email)
    if user is None:
        logger.debug("Password reset requested for unknown email")
        return None

    logger.info("Password reset requested: user_id=%s", user.id)
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
    payload = await token_engine.decode_token(token)

    if payload.extra.get("purpose") != "password_reset":
        logger.warning("Invalid password reset token (wrong purpose)")
        raise TokenError("Invalid password reset token")

    user = await adapter.get_user_by_id(payload.sub)
    if user is None:
        logger.error("Password reset failed — user not found: %s", payload.sub)
        raise UserNotFoundError("User not found")

    hashed = hash_password(new_password)
    await adapter.set_password(str(user.id), hashed)

    # Blacklist the reset token so it can't be reused
    await token_engine.blacklist_token(payload.jti)

    # Revoke all existing sessions so stolen tokens can't be used
    await adapter.revoke_all_user_refresh_tokens(str(user.id))

    logger.info("Password reset completed: user_id=%s", user.id)
    return user
