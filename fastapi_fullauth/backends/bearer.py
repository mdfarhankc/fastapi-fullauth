from __future__ import annotations

from fastapi import Request, Response

from fastapi_fullauth.backends.base import AbstractBackend


class BearerBackend(AbstractBackend):
    """Bearer token backend — reads from Authorization header."""

    async def read_token(self, request: Request) -> str | None:
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            return auth[7:]
        return None

    async def write_token(self, response: Response, token: str) -> None:
        # Bearer tokens are returned in the response body, not set on the response.
        pass

    async def delete_token(self, response: Response) -> None:
        # Nothing to clear for bearer tokens.
        pass
