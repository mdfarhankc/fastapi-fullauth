from typing import Any, ClassVar

from fastapi_fullauth.oauth.base import StandardOAuthProvider
from fastapi_fullauth.types import OAuthUserInfo


class GoogleOAuthProvider(StandardOAuthProvider):
    name = "google"
    display_name = "Google"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
    extra_authorize_params: ClassVar[dict[str, str]] = {
        "access_type": "offline",
        "prompt": "consent",
    }

    @property
    def default_scopes(self) -> list[str]:
        return ["openid", "email", "profile"]

    async def parse_user_info(
        self, data: dict[str, Any], headers: dict[str, str]
    ) -> OAuthUserInfo:
        if not data.get("sub"):
            raise self._invalid_user_info("sub")

        return OAuthUserInfo(
            provider="google",
            provider_user_id=data["sub"],
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            name=data.get("name"),
            picture=data.get("picture"),
            raw=data,
        )
