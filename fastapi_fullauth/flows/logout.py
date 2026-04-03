
from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.types import TokenPayload


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
        if stored:
            await adapter.revoke_refresh_token_family(stored.family_id)
