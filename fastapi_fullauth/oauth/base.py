from abc import ABC, abstractmethod

from fastapi_fullauth.types import OAuthUserInfo


class OAuthProvider(ABC):
    name: str

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or self.default_scopes

    @property
    @abstractmethod
    def default_scopes(self) -> list[str]: ...

    @abstractmethod
    def get_authorization_url(self, state: str) -> str: ...

    @abstractmethod
    async def exchange_code(self, code: str) -> dict: ...

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
