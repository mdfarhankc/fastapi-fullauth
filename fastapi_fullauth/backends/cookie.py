
from fastapi import Request, Response

from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.config import FullAuthConfig


class CookieBackend(AbstractBackend):
    """HttpOnly cookie backend."""

    def __init__(self, config: FullAuthConfig) -> None:
        self.config = config

    async def read_token(self, request: Request) -> str | None:
        return request.cookies.get(self.config.COOKIE_NAME)

    async def write_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.config.COOKIE_NAME,
            value=token,
            httponly=self.config.COOKIE_HTTPONLY,
            secure=self.config.COOKIE_SECURE,
            samesite=self.config.COOKIE_SAMESITE,
            domain=self.config.COOKIE_DOMAIN,
            max_age=self.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def delete_token(self, response: Response) -> None:
        response.delete_cookie(
            key=self.config.COOKIE_NAME,
            domain=self.config.COOKIE_DOMAIN,
        )
