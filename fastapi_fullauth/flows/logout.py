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
    """Blacklist the access token and end the session (its refresh-token family)."""
    await token_engine.blacklist_payload(token_payload)

    # End the session using the family_id carried on the access token, so logout
    # works with just the access credential (the common bearer case) instead of
    # requiring the client to resupply the refresh token.
    if adapter and token_payload.family_id:
        await adapter.revoke_refresh_token_family(token_payload.family_id)
    elif adapter and refresh_token:
        # Fallback for access tokens minted before family_id was carried: revoke
        # via the supplied refresh token, but only when it belongs to the caller;
        # otherwise a valid access token could be used to nuke someone else's family.
        stored = await adapter.get_refresh_token(refresh_token)
        if stored and str(stored.user_id) == token_payload.sub:
            await adapter.revoke_refresh_token_family(stored.family_id)
        elif stored:
            logger.warning(
                "Logout ignored refresh_token; owner mismatch: caller=%s owner=%s",
                token_payload.sub,
                stored.user_id,
            )

    logger.info("Logout: user_id=%s jti=%s", token_payload.sub, token_payload.jti)
