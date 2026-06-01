from typing import Any

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.types import RefreshToken, TokenPair, UserSchema


async def issue_token_pair(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    user: UserSchema,
    *,
    extra_claims: dict[str, Any] | None = None,
    family_id: str | None = None,
    roles: list[str] | None = None,
) -> TokenPair:
    """Create an access/refresh token pair for ``user`` and persist the refresh token.

    Shared by the login, OAuth, passkey, and refresh-rotation flows. Pass
    ``family_id`` to keep an existing refresh-token family (rotation); omit it
    to start a new one. Pass ``roles`` to reuse an already-fetched list and skip
    the lookup.
    """
    if roles is None:
        roles = await adapter.get_user_roles(user.id)

    access, refresh_meta = token_engine.create_token_pair(
        user_id=str(user.id),
        roles=roles,
        extra=extra_claims,
        family_id=family_id,
    )

    await adapter.store_refresh_token(
        RefreshToken(
            token=refresh_meta.token,
            user_id=user.id,
            expires_at=refresh_meta.expires_at,
            family_id=refresh_meta.family_id,
        )
    )

    return TokenPair(
        access_token=access,
        refresh_token=refresh_meta.token,
        expires_in=token_engine.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
