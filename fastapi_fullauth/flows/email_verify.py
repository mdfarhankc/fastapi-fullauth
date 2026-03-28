from __future__ import annotations

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenError, UserNotFoundError


async def create_email_verification_token(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    user_id: str,
) -> str | None:
    """Generate an email verification token. Returns None if user not found."""
    user = await adapter.get_user_by_id(user_id)
    if user is None:
        return None

    token = token_engine.create_access_token(
        user_id=str(user.id),
        extra={"purpose": "email_verify"},
    )
    return token


async def verify_email(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    token: str,
) -> None:
    """Verify a user's email using the verification token."""
    payload = token_engine.decode_token(token)

    if payload.extra.get("purpose") != "email_verify":
        raise TokenError("Invalid email verification token")

    user = await adapter.get_user_by_id(payload.sub)
    if user is None:
        raise UserNotFoundError("User not found")

    if user.is_verified:
        return  # already verified, no-op

    await adapter.set_user_verified(str(user.id))

    # blacklist the token so it can't be reused
    token_engine.blacklist_token(payload.jti)
