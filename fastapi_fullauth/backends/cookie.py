from typing import Any, Literal

from fastapi import Request, Response

from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.config import FullAuthConfig


class CookieBackend(AbstractBackend):
    def __init__(
        self,
        config: FullAuthConfig,
        *,
        name: str = "fullauth_access",
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
        domain: str | None = None,
    ) -> None:
        self.config = config
        self.name = name
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite
        self.domain = domain

    async def read_token(self, request: Request) -> str | None:
        return request.cookies.get(self.name)

    async def write_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.name,
            value=token,
            max_age=self.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            **self._cookie_attrs(),
        )

    async def delete_token(self, response: Response) -> None:
        # Browsers ignore the deletion unless the attributes (secure, samesite,
        # path, domain) match the cookie being replaced; Chrome outright rejects
        # a SameSite=None set-cookie without Secure.
        response.delete_cookie(key=self.name, **self._cookie_attrs())

    def _cookie_attrs(self) -> dict[str, Any]:
        return {
            "httponly": self.httponly,
            "secure": self.secure,
            "samesite": self.samesite,
            "domain": self.domain,
            "path": "/",
        }
