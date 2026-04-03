
from abc import ABC, abstractmethod

from fastapi import Request, Response


class AbstractBackend(ABC):
    """Interface for authentication transport backends."""

    @abstractmethod
    async def read_token(self, request: Request) -> str | None:
        """Extract the token from the incoming request."""
        ...

    @abstractmethod
    async def write_token(self, response: Response, token: str) -> None:
        """Attach the token to the outgoing response."""
        ...

    @abstractmethod
    async def delete_token(self, response: Response) -> None:
        """Remove the token from the outgoing response (logout)."""
        ...
