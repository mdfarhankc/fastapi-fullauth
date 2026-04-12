import logging
from urllib.parse import urlencode

from fastapi_fullauth.exceptions import OAuthProviderError
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo

logger = logging.getLogger("fastapi_fullauth.oauth.google")


class GoogleOAuthProvider(OAuthProvider):
    name = "google"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"

    @property
    def default_scopes(self) -> list[str]:
        return ["openid", "email", "profile"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        async with self._get_http_client() as client:
            resp = await client.post(
                self.token_endpoint,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
            if resp.status_code != 200:
                logger.error(
                    "Google token exchange failed (HTTP %s): %s", resp.status_code, resp.text
                )
                raise OAuthProviderError("Google token exchange failed")
            return resp.json()

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        access_token = tokens["access_token"]
        async with self._get_http_client() as client:
            resp = await client.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                logger.error("Google userinfo failed (HTTP %s): %s", resp.status_code, resp.text)
                raise OAuthProviderError("Failed to fetch user info from Google")
            data = resp.json()

        return OAuthUserInfo(
            provider="google",
            provider_user_id=data["sub"],
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            name=data.get("name"),
            picture=data.get("picture"),
            raw=data,
        )
