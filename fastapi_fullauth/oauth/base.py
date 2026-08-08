import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlencode

from fastapi_fullauth.exceptions import OAuthProviderError
from fastapi_fullauth.types import OAuthUserInfo

if TYPE_CHECKING:
    import httpx


class OAuthProvider(ABC):
    name: str
    # Whether this provider supports PKCE (RFC 7636). When True, the OAuth flow
    # sends a code_challenge on authorize and a code_verifier on token exchange.
    # Left False for custom providers so their existing method signatures keep
    # working without the PKCE keyword arguments.
    supports_pkce: bool = False
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
    def get_authorization_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str: ...

    @abstractmethod
    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]: ...

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
            # An explicit timeout so a slow or hostile provider can't tie up the
            # request worker indefinitely (don't rely on the library default).
            self._http_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        return self._http_client

    async def aclose(self) -> None:
        """Close the shared HTTP client. Safe to call more than once."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None


class StandardOAuthProvider(OAuthProvider):
    """OAuth2 authorization-code provider with the standard endpoint shape.

    Implements the authorize-URL, code-exchange, and userinfo steps generically;
    a concrete provider supplies the three endpoints, ``default_scopes``, and
    ``parse_user_info`` to map the userinfo payload to :class:`OAuthUserInfo`.
    Providers that deviate from the standard wire format override the small
    ``_authorize_params`` / ``_token_request_body`` hooks instead of the whole
    method (see the GitHub provider).
    """

    supports_pkce = True
    # Human-readable provider name used in log and error messages.
    display_name: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    # Extra provider-specific query params for the authorize URL
    # (e.g. Google's access_type/prompt).
    extra_authorize_params: ClassVar[dict[str, str]] = {}

    @property
    def _logger(self) -> logging.Logger:
        # Named per provider ("fastapi_fullauth.oauth.<name>") so deployments
        # can raise or filter one provider's log level independently.
        return logging.getLogger(f"fastapi_fullauth.oauth.{self.name}")

    def _authorize_params(self, state: str, redirect_uri: str) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            **self.extra_authorize_params,
        }

    def _token_request_body(self, code: str, redirect_uri: str) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

    def get_authorization_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = self._authorize_params(state, redirect_uri)
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        body = self._token_request_body(code, redirect_uri)
        if code_verifier:
            body["code_verifier"] = code_verifier
        resp = await self._client().post(
            self.token_endpoint,
            data=body,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            # Don't log resp.text: token-endpoint error bodies can echo the code
            # or client credentials. Status is enough to diagnose.
            self._logger.error(
                "%s token exchange failed (HTTP %s)", self.display_name, resp.status_code
            )
            raise OAuthProviderError(f"{self.display_name} token exchange failed")
        data: dict[str, Any] = resp.json()
        # Some providers (GitHub) return errors with HTTP 200 and an `error` body.
        if "error" in data:
            self._logger.error(
                "%s token error: %s",
                self.display_name,
                data.get("error_description", data["error"]),
            )
            raise OAuthProviderError(f"{self.display_name} token exchange failed")
        return data

    async def get_user_info(self, tokens: dict[str, Any]) -> OAuthUserInfo:
        access_token = tokens.get("access_token")
        if not access_token:
            self._logger.error("%s token response missing access_token", self.display_name)
            raise OAuthProviderError(f"{self.display_name} token exchange failed")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        resp = await self._client().get(self.userinfo_endpoint, headers=headers)
        if resp.status_code != 200:
            self._logger.error("%s userinfo failed (HTTP %s)", self.display_name, resp.status_code)
            raise OAuthProviderError(f"Failed to fetch user info from {self.display_name}")
        return await self.parse_user_info(resp.json(), headers)

    def _invalid_user_info(self, missing: str) -> OAuthProviderError:
        self._logger.error("%s userinfo response missing %s", self.display_name, missing)
        return OAuthProviderError(f"Failed to fetch user info from {self.display_name}")

    @abstractmethod
    async def parse_user_info(self, data: dict[str, Any], headers: dict[str, str]) -> OAuthUserInfo:
        """Map the provider's userinfo payload to :class:`OAuthUserInfo`.

        ``headers`` carries the authenticated headers used for the userinfo
        request, for providers that need follow-up API calls (GitHub's email
        endpoint). Raise ``self._invalid_user_info(...)`` when a required
        field is absent.
        """
