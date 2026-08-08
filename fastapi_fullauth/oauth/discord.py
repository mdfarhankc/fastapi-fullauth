from typing import Any

from fastapi_fullauth.oauth.base import StandardOAuthProvider
from fastapi_fullauth.types import OAuthUserInfo


class DiscordOAuthProvider(StandardOAuthProvider):
    name = "discord"
    display_name = "Discord"
    authorization_endpoint = "https://discord.com/oauth2/authorize"
    token_endpoint = "https://discord.com/api/oauth2/token"
    userinfo_endpoint = "https://discord.com/api/users/@me"
    cdn_base = "https://cdn.discordapp.com"

    @property
    def default_scopes(self) -> list[str]:
        return ["identify", "email"]

    async def parse_user_info(self, data: dict[str, Any], headers: dict[str, str]) -> OAuthUserInfo:
        user_id = data.get("id")
        if not user_id:
            raise self._invalid_user_info("id")

        # avatar is a hash; build the CDN URL. None for accounts with no avatar.
        avatar = data.get("avatar")
        picture = f"{self.cdn_base}/avatars/{user_id}/{avatar}.png" if avatar else None

        return OAuthUserInfo(
            provider="discord",
            provider_user_id=str(user_id),
            email=data.get("email"),
            # `verified` is only present when the `email` scope is granted; it
            # reflects whether the account's email address is verified.
            email_verified=bool(data.get("verified", False)),
            # global_name is the current display name; fall back to the username.
            name=data.get("global_name") or data.get("username"),
            picture=picture,
            raw=data,
        )
