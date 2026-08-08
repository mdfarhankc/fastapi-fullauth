from fastapi_fullauth.oauth.base import OAuthProvider, StandardOAuthProvider
from fastapi_fullauth.oauth.discord import DiscordOAuthProvider
from fastapi_fullauth.oauth.github import GitHubOAuthProvider
from fastapi_fullauth.oauth.gitlab import GitLabOAuthProvider
from fastapi_fullauth.oauth.google import GoogleOAuthProvider

__all__ = [
    "DiscordOAuthProvider",
    "GitHubOAuthProvider",
    "GitLabOAuthProvider",
    "GoogleOAuthProvider",
    "OAuthProvider",
    "StandardOAuthProvider",
]
