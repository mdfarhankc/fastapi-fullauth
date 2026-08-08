from typing import Any

from fastapi_fullauth.oauth.base import StandardOAuthProvider
from fastapi_fullauth.types import OAuthUserInfo


class GitHubOAuthProvider(StandardOAuthProvider):
    name = "github"
    display_name = "GitHub"
    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    emails_endpoint = "https://api.github.com/user/emails"

    @property
    def default_scopes(self) -> list[str]:
        return ["read:user", "user:email"]

    def _authorize_params(self, state: str, redirect_uri: str) -> dict[str, str]:
        # GitHub's authorize endpoint doesn't take response_type.
        params = super()._authorize_params(state, redirect_uri)
        del params["response_type"]
        return params

    def _token_request_body(self, code: str, redirect_uri: str) -> dict[str, str]:
        # GitHub's token endpoint takes neither grant_type nor redirect_uri.
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
        }

    async def parse_user_info(
        self, data: dict[str, Any], headers: dict[str, str]
    ) -> OAuthUserInfo:
        # GitHub needs a separate call for the verified primary email
        email = data.get("email")
        email_verified = False

        emails_resp = await self._client().get(self.emails_endpoint, headers=headers)
        if emails_resp.status_code == 200:
            for entry in emails_resp.json():
                if entry.get("primary") and entry.get("verified"):
                    email = entry["email"]
                    email_verified = True
                    break

        if data.get("id") is None:
            raise self._invalid_user_info("id")

        return OAuthUserInfo(
            provider="github",
            provider_user_id=str(data["id"]),
            email=email,
            email_verified=email_verified,
            name=data.get("name"),
            picture=data.get("avatar_url"),
            raw=data,
        )
