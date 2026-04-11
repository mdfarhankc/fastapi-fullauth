import logging
from urllib.parse import urlencode

from fastapi_fullauth.exceptions import OAuthProviderError
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo

logger = logging.getLogger("fastapi_fullauth.oauth.github")


class GitHubOAuthProvider(OAuthProvider):
    name = "github"
    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    emails_endpoint = "https://api.github.com/user/emails"

    @property
    def default_scopes(self) -> list[str]:
        return ["read:user", "user:email"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
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
                },
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                logger.error("GitHub token exchange failed (HTTP %s): %s",
                             resp.status_code, resp.text)
                raise OAuthProviderError("GitHub token exchange failed")
            data = resp.json()
            if "error" in data:
                logger.error("GitHub token error: %s", data.get("error_description", data["error"]))
                raise OAuthProviderError("GitHub token exchange failed")
            return data

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        access_token = tokens["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with self._get_http_client() as client:
            resp = await client.get(self.userinfo_endpoint, headers=headers)
            if resp.status_code != 200:
                logger.error("GitHub userinfo failed (HTTP %s): %s",
                             resp.status_code, resp.text)
                raise OAuthProviderError("Failed to fetch user info from GitHub")
            data = resp.json()

            # GitHub needs a separate call for verified primary email
            email = data.get("email")
            email_verified = False

            emails_resp = await client.get(self.emails_endpoint, headers=headers)
            if emails_resp.status_code == 200:
                for entry in emails_resp.json():
                    if entry.get("primary") and entry.get("verified"):
                        email = entry["email"]
                        email_verified = True
                        break

        return OAuthUserInfo(
            provider="github",
            provider_user_id=str(data["id"]),
            email=email,
            email_verified=email_verified,
            name=data.get("name"),
            picture=data.get("avatar_url"),
            raw=data,
        )
