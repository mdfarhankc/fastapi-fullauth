"""Shared token-transport helpers for the auth, OAuth, and passkey routers.

These move tokens through the configured backends (bearer header, cookie, ...)
and keep the refresh token out of the JSON body when a backend carries it.
"""

from typing import TYPE_CHECKING

from fastapi import Request, Response

from fastapi_fullauth.types import TokenPair

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def backend_carries_refresh(fullauth: "FullAuth") -> bool:
    return any(b.handles_refresh_token for b in fullauth.backends)


async def resolve_refresh_token(
    request: Request, fullauth: "FullAuth", body_token: str | None
) -> str | None:
    """Resolve the incoming refresh token from a backend (cookie) first, then
    fall back to the request body."""
    for backend in fullauth.backends:
        token = await backend.read_refresh_token(request)
        if token:
            return token
    return body_token


async def write_tokens(response: Response, fullauth: "FullAuth", tokens: TokenPair) -> TokenPair:
    """Write the access token (and the refresh token, for backends that carry it)
    onto the response. When a backend carries the refresh token, blank it out of
    the returned body so it never reaches JavaScript."""
    for backend in fullauth.backends:
        await backend.write_token(response, tokens.access_token)
        if tokens.refresh_token is not None:
            await backend.write_refresh_token(response, tokens.refresh_token)
    if backend_carries_refresh(fullauth):
        return tokens.model_copy(update={"refresh_token": None})
    return tokens
