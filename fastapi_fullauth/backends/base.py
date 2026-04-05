from abc import ABC, abstractmethod

from fastapi import Request, Response


class AbstractBackend(ABC):
    @abstractmethod
    async def read_token(self, request: Request) -> str | None: ...

    @abstractmethod
    async def write_token(self, response: Response, token: str) -> None: ...

    @abstractmethod
    async def delete_token(self, response: Response) -> None: ...
