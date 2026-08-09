import logging

from pydantic import ValidationError

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_refresh_token
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import (
    AuthenticationError,
    RefreshTokenReuseError,
    TokenError,
)
from fastapi_fullauth.flows.tokens import ClaimsProvider, issue_token_pair
from fastapi_fullauth.types import TokenPair

logger = logging.getLogger("fastapi_fullauth.refresh")


async def refresh(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    refresh_token: str,
    *,
    extra_claims_provider: ClaimsProvider | None = None,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> TokenPair:
    """Exchange a refresh token for a new token pair.

    With ``REFRESH_TOKEN_ROTATION`` enabled the presented token is revoked and
    replaced atomically; presenting an already-used token burns its whole family
    and raises :class:`RefreshTokenReuseError`. Without rotation the same
    refresh token is returned alongside a fresh access token.

    Raises :class:`TokenError` for invalid/expired/blacklisted tokens and
    :class:`AuthenticationError` for unknown/inactive users or unbacked tokens.
    """
    payload = await token_engine.decode_token(refresh_token, expected_type="refresh")

    try:
        user_id = adapter.parse_user_id(payload.sub)
    except (ValueError, ValidationError):
        raise TokenError("Invalid subject claim")

    user = await adapter.get_user_by_id(user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Unknown or inactive user")

    # Tokens are stored as sha256 digests; hash the presented token to look it up.
    token_digest = hash_refresh_token(refresh_token)
    stored = await adapter.get_refresh_token(token_digest)
    # Defence in depth: the refresh JWT may decode cleanly (valid signature,
    # unexpired) and still not correspond to a stored session; e.g. an old
    # row pruned, or a token issued before the row was deleted. Reject so
    # signed-but-unbacked tokens can't mint new access tokens.
    if stored is None:
        raise AuthenticationError("Refresh token has no backing session")

    roles = await adapter.get_user_roles(user.id)
    extra_claims = await extra_claims_provider(user) if extra_claims_provider else {}
    config = token_engine.config

    if config.REFRESH_TOKEN_ROTATION:
        # Revoking the old token and storing its replacement must be atomic:
        # a crash between them would revoke the family's only live token and
        # persist no successor, silently orphaning the session. Run both in
        # one transaction; the compare-and-swap still picks the winner via the
        # UPDATE rowcount (a flush inside the transaction exposes it).
        won = False
        tokens: TokenPair | None = None
        async with adapter.transaction() as tx:
            # Exactly one concurrent caller flips the token not-revoked →
            # revoked. The loser sees rowcount=0 - reuse attack or lost race -
            # and burns the family below.
            won = await tx.revoke_refresh_token(token_digest)
            if won:
                tokens = await issue_token_pair(
                    tx,
                    token_engine,
                    user,
                    extra_claims=extra_claims,
                    family_id=payload.family_id,
                    roles=roles,
                    user_agent=user_agent,
                    ip_address=ip_address,
                )

        if not won or tokens is None:
            logger.error(
                "refresh token reuse/concurrent use; revoking family: %s",
                stored.family_id,
            )
            await adapter.revoke_refresh_token_family(stored.family_id)
            raise RefreshTokenReuseError("Refresh token already used; family revoked")

        await token_engine.blacklist_token(
            payload.jti,
            ttl_seconds=config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        )
        return tokens

    if stored.revoked:
        raise AuthenticationError("Refresh token has been revoked")

    access = token_engine.create_access_token(
        user_id=str(user.id),
        roles=roles,
        extra=extra_claims,
        family_id=payload.family_id,
    )
    return TokenPair(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
