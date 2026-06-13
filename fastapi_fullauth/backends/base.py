from abc import ABC, abstractmethod

from fastapi import Request, Response


class AbstractBackend(ABC):
    # Whether this backend transports the refresh token. When True, the auth
    # routes write the refresh token through the backend and keep it out of the
    # JSON response body; when False (the default) the refresh token travels in
    # the request/response body as before.
    handles_refresh_token: bool = False

    @abstractmethod
    async def read_token(self, request: Request) -> str | None: ...

    @abstractmethod
    async def write_token(self, response: Response, token: str) -> None: ...

    @abstractmethod
    async def delete_token(self, response: Response) -> None: ...

    async def read_refresh_token(self, request: Request) -> str | None:
        """Read the refresh token this backend carries. Defaults to None, so the
        route falls back to the request body."""
        return None

    async def write_refresh_token(self, response: Response, token: str) -> None:  # noqa: B027
        """Persist the refresh token on the response. Intentionally a no-op by
        default (the token stays in the body); cookie backends override it."""

    async def delete_refresh_token(self, response: Response) -> None:  # noqa: B027
        """Clear the carried refresh token. Intentional no-op by default."""
