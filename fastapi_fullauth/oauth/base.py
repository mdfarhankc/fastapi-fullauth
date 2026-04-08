from abc import ABC, abstractmethod

from fastapi_fullauth.types import OAuthUserInfo


class OAuthProvider(ABC):
    name: str

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str | None = None,
        redirect_uris: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        if redirect_uris:
            self.redirect_uris = redirect_uris
        elif redirect_uri:
            self.redirect_uris = [redirect_uri]
        else:
            raise ValueError("Either redirect_uri or redirect_uris must be provided")
        self.scopes = scopes or self.default_scopes

    def get_redirect_uri(self, requested: str | None = None) -> str:
        if requested is None:
            return self.redirect_uris[0]
        if requested not in self.redirect_uris:
            raise ValueError(f"redirect_uri '{requested}' is not in the allowed list")
        return requested

    @property
    @abstractmethod
    def default_scopes(self) -> list[str]: ...

    @abstractmethod
    def get_authorization_url(self, state: str, redirect_uri: str) -> str: ...

    @abstractmethod
    async def exchange_code(self, code: str, redirect_uri: str) -> dict: ...

    @abstractmethod
    async def get_user_info(self, tokens: dict) -> OAuthUserInfo: ...

    @staticmethod
    def _get_http_client():
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for OAuth. Install it with: pip install fastapi-fullauth[oauth]"
            ) from None
        return httpx.AsyncClient()
