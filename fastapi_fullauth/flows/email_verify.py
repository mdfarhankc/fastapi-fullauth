import logging
from uuid import UUID

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenError, UserNotFoundError
from fastapi_fullauth.types import UserID, UserSchema

logger = logging.getLogger("fastapi_fullauth.email_verify")


async def create_email_verification_token(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    user_id: UserID,
) -> str | None:
    """Generate an email verification token. Returns None if user not found."""
    user = await adapter.get_user_by_id(user_id)
    if user is None:
        return None

    token = token_engine.create_access_token(
        user_id=str(user.id),
        extra={"purpose": "email_verify"},
        expire_seconds=token_engine.config.EMAIL_VERIFY_EXPIRE_MINUTES * 60,
    )
    return token


async def verify_email(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    token: str,
) -> UserSchema | None:
    """Verify a user's email using the verification token. Returns the user."""
    payload = await token_engine.decode_token(
        token, expected_type="access", expected_purpose="email_verify"
    )

    try:
        user_id = UUID(payload.sub)
    except ValueError:
        raise TokenError("Invalid email verification token")

    user = await adapter.get_user_by_id(user_id)
    if user is None:
        logger.error("Email verification failed; user not found: %s", payload.sub)
        raise UserNotFoundError("User not found")

    # Burn the token on any successful resolution - including the already-verified
    # no-op - so a still-live verification token can't be replayed later.
    await token_engine.blacklist_payload(payload)

    # Parity with login/OAuth: don't act on a deactivated account.
    if not user.is_active:
        logger.warning("Email verification blocked; account deactivated: user_id=%s", user.id)
        raise TokenError("User account is deactivated")

    if user.is_verified:
        return user  # already verified, no-op

    await adapter.set_user_verified(user.id)

    logger.info("Email verified: user_id=%s", user.id)
    return user.model_copy(update={"is_verified": True})
