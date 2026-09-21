import hashlib
import hmac
import logging
from typing import Literal

from pydantic import ValidationError

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import ahash_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenError, UserNotFoundError
from fastapi_fullauth.flows.sessions import revoke_user_session_tokens
from fastapi_fullauth.types import UserSchema
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth.password_reset")


def _password_fingerprint(hashed_password: str | None) -> str:
    """Digest of the password hash the reset token was issued against.

    Carried in the token so that changing the password - through another reset
    link, /change-password, or using this one - invalidates every other
    outstanding link, without a table of issued tokens to keep. It is a digest of
    a digest, so the token reveals nothing about the password.
    """
    return hashlib.sha256((hashed_password or "").encode()).hexdigest()[:32]


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
    fingerprint = _password_fingerprint(await adapter.get_hashed_password(user.id))
    token = token_engine.create_access_token(
        user_id=str(user.id),
        extra={"purpose": "password_reset", "pwd": fingerprint},
        expire_seconds=token_engine.config.PASSWORD_RESET_EXPIRE_MINUTES * 60,
    )
    return token


async def reset_password(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    token: str,
    new_password: str,
    hash_algorithm: Literal["argon2id", "bcrypt"] = "argon2id",
    password_validator: PasswordValidator | None = None,
) -> UserSchema | None:
    payload = await token_engine.decode_token(
        token, expected_type="access", expected_purpose="password_reset"
    )

    if password_validator:
        password_validator.validate(new_password)

    try:
        user_id = adapter.parse_user_id(payload.sub)
    except (ValueError, ValidationError):
        raise TokenError("Invalid password reset token")

    user = await adapter.get_user_by_id(user_id)
    if user is None:
        logger.error("Password reset failed; user not found: %s", payload.sub)
        raise UserNotFoundError("User not found")

    # Parity with login/OAuth: a deactivated account must not be actionable.
    # Burn the token first so this rejection can't be retried with the same one.
    if not user.is_active:
        await token_engine.blacklist_payload(payload)
        logger.warning("Password reset blocked; account deactivated: user_id=%s", user.id)
        raise TokenError("User account is deactivated")

    # A token issued against a password that has since changed is stale: another
    # reset link was used, or the user changed it themselves. Reject it rather
    # than let an old link out of an inbox undo a deliberate change.
    presented = payload.extra.get("pwd")
    expected = _password_fingerprint(await adapter.get_hashed_password(user.id))
    if not isinstance(presented, str) or not hmac.compare_digest(presented, expected):
        await token_engine.blacklist_payload(payload)
        logger.warning("Password reset rejected; stale token: user_id=%s", user.id)
        raise TokenError("Invalid password reset token")

    hashed = await ahash_password(new_password, algorithm=hash_algorithm)
    await adapter.set_password(user.id, hashed)

    # Blacklist the reset token so it can't be reused, for its remaining lifetime
    await token_engine.blacklist_payload(payload)

    # End every existing session, including access tokens already issued, so a
    # stolen session can't outlive the reset. Tokens first: only live sessions list.
    await revoke_user_session_tokens(adapter, token_engine, user.id)
    await adapter.revoke_all_user_refresh_tokens(user.id)

    logger.info("Password reset completed: user_id=%s", user.id)
    return user
