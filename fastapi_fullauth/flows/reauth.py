"""Proof that the person behind a session is still there.

A valid access token says a session exists, not that whoever holds it just
proved who they are. Actions that cannot be undone ask for more: either the
current password, or a session whose credentials were checked recently.
"""

import logging
from datetime import datetime, timezone

from fastapi_fullauth.core.crypto import averify_password
from fastapi_fullauth.exceptions import AuthenticationError
from fastapi_fullauth.types import TokenPayload

logger = logging.getLogger("fastapi_fullauth.reauth")


async def verify_recent_auth(
    payload: TokenPayload,
    *,
    hashed_password: str | None,
    current_password: str | None = None,
    max_age_seconds: int = 300,
    max_password_length: int = 0,
) -> None:
    """Raise :class:`AuthenticationError` unless the caller has proved presence.

    Either proof is enough:

    - ``current_password`` matches the stored hash, or
    - the session's credentials were checked within ``max_age_seconds``.

    The age comes from the token's ``auth_time``, which is stamped when
    credentials are checked and carried through refresh rotation, so refreshing
    a stolen token does not renew it. Tokens issued before ``auth_time`` existed
    fall back to ``iat``.
    """
    # A blank field means the client did not ask to prove it this way; fall
    # through to the session's age rather than failing the request.
    if hashed_password is not None and current_password:
        # Capped before hashing, for the same reason login caps it.
        if max_password_length and len(current_password) > max_password_length:
            logger.warning("Re-authentication failed; password too long: sub=%s", payload.sub)
            raise AuthenticationError("Current password is incorrect")
        if await averify_password(current_password, hashed_password):
            return
        logger.warning("Re-authentication failed; wrong password: sub=%s", payload.sub)
        raise AuthenticationError("Current password is incorrect")

    if max_age_seconds > 0:
        checked_at = payload.auth_time or payload.iat
        age = (datetime.now(timezone.utc) - checked_at).total_seconds()
        if age <= max_age_seconds:
            return

    logger.info("Re-authentication required: sub=%s", payload.sub)
    raise AuthenticationError("Re-authentication required")
