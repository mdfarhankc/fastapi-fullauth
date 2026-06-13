import logging
from typing import Any
from urllib.parse import urlencode

from fastapi_fullauth.exceptions import OAuthProviderError
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo

logger = logging.getLogger("fastapi_fullauth.oauth.github")


class GitHubOAuthProvider(OAuthProvider):
    name = "github"
    supports_pkce = True
    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    emails_endpoint = "https://api.github.com/user/emails"

    @property
    def default_scopes(self) -> list[str]:
        return ["read:user", "user:email"]

    def get_authorization_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
        }
        if code_verifier:
            body["code_verifier"] = code_verifier
        client = self._client()
        resp = await client.post(
            self.token_endpoint,
            data=body,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            logger.error("GitHub token exchange failed (HTTP %s): %s", resp.status_code, resp.text)
            raise OAuthProviderError("GitHub token exchange failed")
        data: dict[str, Any] = resp.json()
        if "error" in data:
            logger.error("GitHub token error: %s", data.get("error_description", data["error"]))
            raise OAuthProviderError("GitHub token exchange failed")
        return data

    async def get_user_info(self, tokens: dict[str, Any]) -> OAuthUserInfo:
        access_token = tokens.get("access_token")
        if not access_token:
            logger.error("GitHub token response missing access_token")
            raise OAuthProviderError("GitHub token exchange failed")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        client = self._client()
        resp = await client.get(self.userinfo_endpoint, headers=headers)
        if resp.status_code != 200:
            logger.error("GitHub userinfo failed (HTTP %s): %s", resp.status_code, resp.text)
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

        if data.get("id") is None:
            logger.error("GitHub userinfo response missing id")
            raise OAuthProviderError("Failed to fetch user info from GitHub")

        return OAuthUserInfo(
            provider="github",
            provider_user_id=str(data["id"]),
            email=email,
            email_verified=email_verified,
            name=data.get("name"),
            picture=data.get("avatar_url"),
            raw=data,
        )
