from typing import Any

from fastapi_fullauth.oauth.base import StandardOAuthProvider
from fastapi_fullauth.types import OAuthUserInfo


class GitLabOAuthProvider(StandardOAuthProvider):
    name = "gitlab"
    display_name = "GitLab"
    # gitlab.com defaults. For a self-hosted GitLab, subclass and override these
    # three endpoints with your instance URL.
    authorization_endpoint = "https://gitlab.com/oauth/authorize"
    token_endpoint = "https://gitlab.com/oauth/token"
    userinfo_endpoint = "https://gitlab.com/oauth/userinfo"

    @property
    def default_scopes(self) -> list[str]:
        return ["openid", "email", "profile"]

    async def parse_user_info(self, data: dict[str, Any], headers: dict[str, str]) -> OAuthUserInfo:
        if not data.get("sub"):
            raise self._invalid_user_info("sub")

        return OAuthUserInfo(
            provider="gitlab",
            provider_user_id=str(data["sub"]),
            email=data.get("email"),
            email_verified=bool(data.get("email_verified", False)),
            name=data.get("name"),
            picture=data.get("picture"),
            raw=data,
        )
