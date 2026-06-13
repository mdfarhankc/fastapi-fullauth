from typing import Any, Literal

from fastapi import Request, Response

from fastapi_fullauth.backends.base import AbstractBackend
from fastapi_fullauth.config import FullAuthConfig


class CookieBackend(AbstractBackend):
    handles_refresh_token = True

    def __init__(
        self,
        config: FullAuthConfig,
        *,
        name: str = "fullauth_access",
        refresh_name: str = "fullauth_refresh",
        refresh_path: str = "/",
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
        domain: str | None = None,
    ) -> None:
        if samesite == "none" and not secure:
            raise ValueError(
                "CookieBackend with samesite='none' requires secure=True; browsers "
                "reject a SameSite=None cookie that is not also Secure."
            )
        self.config = config
        self.name = name
        self.refresh_name = refresh_name
        # Scope the refresh cookie. Defaults to "/"; set it to your auth prefix
        # (e.g. "/api/v1/auth") so the browser only sends the refresh token to
        # the refresh/logout routes instead of every request.
        self.refresh_path = refresh_path
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

    async def read_refresh_token(self, request: Request) -> str | None:
        return request.cookies.get(self.refresh_name)

    async def write_refresh_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.refresh_name,
            value=token,
            max_age=self.config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            **self._refresh_cookie_attrs(),
        )

    async def delete_refresh_token(self, response: Response) -> None:
        response.delete_cookie(key=self.refresh_name, **self._refresh_cookie_attrs())

    def _cookie_attrs(self) -> dict[str, Any]:
        return {
            "httponly": self.httponly,
            "secure": self.secure,
            "samesite": self.samesite,
            "domain": self.domain,
            "path": "/",
        }

    def _refresh_cookie_attrs(self) -> dict[str, Any]:
        return {**self._cookie_attrs(), "path": self.refresh_path}
