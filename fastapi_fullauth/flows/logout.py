import logging

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.types import TokenPayload

logger = logging.getLogger("fastapi_fullauth.logout")


async def logout(
    token_engine: TokenEngine,
    token_payload: TokenPayload,
    adapter: AbstractUserAdapter | None = None,
    refresh_token: str | None = None,
) -> None:
    """Blacklist the access token and optionally revoke the refresh token family."""
    await token_engine.blacklist_token(token_payload.jti)

    if adapter and refresh_token:
        stored = await adapter.get_refresh_token(refresh_token)
        # Only revoke when the refresh token belongs to the authenticated user;
        # otherwise a valid access token could be used to nuke someone else's family.
        if stored and str(stored.user_id) == token_payload.sub:
            await adapter.revoke_refresh_token_family(stored.family_id)
        elif stored:
            logger.warning(
                "Logout ignored refresh_token = owner mismatch: caller=%s owner=%s",
                token_payload.sub,
                stored.user_id,
            )

    logger.info("Logout: user_id=%s jti=%s", token_payload.sub, token_payload.jti)
