from fastapi import Request, Response

from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.config import FullAuthConfig


class CookieBackend(AbstractBackend):
    def __init__(self, config: FullAuthConfig) -> None:
        self.config = config

    async def read_token(self, request: Request) -> str | None:
        return request.cookies.get(self.config.COOKIE_NAME)

    async def write_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.config.COOKIE_NAME,
            value=token,
            max_age=self.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            **self._cookie_attrs(),
        )

    async def delete_token(self, response: Response) -> None:
        # Browsers ignore the deletion unless the attributes (secure, samesite,
        # path, domain) match the cookie being replaced — Chrome outright rejects
        # a SameSite=None set-cookie without Secure.
        response.delete_cookie(key=self.config.COOKIE_NAME, **self._cookie_attrs())

    def _cookie_attrs(self) -> dict:
        return {
            "httponly": self.config.COOKIE_HTTPONLY,
            "secure": self.config.COOKIE_SECURE,
            "samesite": self.config.COOKIE_SAMESITE,
            "domain": self.config.COOKIE_DOMAIN,
            "path": "/",
        }
