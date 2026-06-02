from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from fastapi_fullauth.types import OAuthUserInfo

if TYPE_CHECKING:
    import httpx


class OAuthProvider(ABC):
    name: str
    # Class-level default so aclose()/_client() are safe even on subclasses that
    # don't call super().__init__().
    _http_client: "httpx.AsyncClient | None" = None

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uris: list[str],
        scopes: list[str] | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        if not redirect_uris:
            raise ValueError("redirect_uris must contain at least one URL")
        self.redirect_uris = redirect_uris
        self.scopes = scopes or self.default_scopes

    @property
    @abstractmethod
    def default_scopes(self) -> list[str]: ...

    @abstractmethod
    def get_authorization_url(self, state: str, redirect_uri: str) -> str: ...

    @abstractmethod
    async def exchange_code(self, code: str, redirect_uri: str) -> dict[str, Any]: ...

    @abstractmethod
    async def get_user_info(self, tokens: dict[str, Any]) -> OAuthUserInfo: ...

    def _client(self) -> "httpx.AsyncClient":
        """Return a shared HTTP client, created lazily and reused across calls."""
        if self._http_client is None:
            try:
                import httpx
            except ImportError:
                raise ImportError(
                    "httpx is required for OAuth. "
                    "Install it with: pip install fastapi-fullauth[oauth]"
                ) from None
            self._http_client = httpx.AsyncClient()
        return self._http_client

    async def aclose(self) -> None:
        """Close the shared HTTP client. Safe to call more than once."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
