import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from fastapi_fullauth.dependencies.current_user import CurrentUser, _get_fullauth
from fastapi_fullauth.exceptions import (
    OAUTH_ERROR_EXCEPTION,
    OAuthProviderError,
    TokenError,
)
from fastapi_fullauth.flows.oauth import generate_oauth_state, oauth_callback
from fastapi_fullauth.router._models import build_login_response_model
from fastapi_fullauth.types import TokenPair, UserSchema, UserSchemaType

logger = logging.getLogger("fastapi_fullauth.oauth")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str


class OAuthProviderListResponse(BaseModel):
    providers: list[str]


class OAuthAuthorizeResponse(BaseModel):
    authorization_url: str


class OAuthAccountResponse(BaseModel):
    provider: str
    provider_user_id: str
    provider_email: str | None = None


def create_oauth_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
) -> APIRouter:
    LoginResponse = build_login_response_model(user_schema)  # noqa: N806
    router = APIRouter()

    @router.get(
        "/oauth/providers",
        status_code=200,
        response_model=OAuthProviderListResponse,
        description="List configured OAuth providers.",
    )
    async def list_providers(
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> OAuthProviderListResponse:
        return OAuthProviderListResponse(providers=list(fullauth.oauth_providers.keys()))

    @router.get(
        "/oauth/{provider}/authorize",
        status_code=200,
        response_model=OAuthAuthorizeResponse,
        description="Get the authorization URL for an OAuth provider.",
    )
    async def authorize(
        provider: str,
        redirect_uri: str,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> OAuthAuthorizeResponse:
        oauth_provider = fullauth.oauth_providers.get(provider)
        if oauth_provider is None:
            raise HTTPException(
                status_code=404, detail=f"OAuth provider '{provider}' not configured"
            )

        if redirect_uri not in oauth_provider.redirect_uris:
            raise HTTPException(status_code=400, detail="Invalid redirect URI")

        state = generate_oauth_state(
            fullauth.token_engine,
            ttl_seconds=fullauth.config.OAUTH_STATE_EXPIRE_SECONDS,
            redirect_uri=redirect_uri,
        )
        url = oauth_provider.get_authorization_url(state, redirect_uri)
        return OAuthAuthorizeResponse(authorization_url=url)

    @router.post(
        "/oauth/{provider}/callback",
        status_code=200,
        response_model=LoginResponse,
        description="Exchange OAuth authorization code for tokens.",
    )
    async def callback(
        provider: str,
        data: OAuthCallbackRequest,
        response: Response,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> TokenPair:
        oauth_provider = fullauth.oauth_providers.get(provider)
        if oauth_provider is None:
            raise HTTPException(
                status_code=404, detail=f"OAuth provider '{provider}' not configured"
            )

        try:
            token_pair, user, is_new_user, user_info = await oauth_callback(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                provider=oauth_provider,
                code=data.code,
                state=data.state,
                auto_link_by_email=fullauth.config.OAUTH_AUTO_LINK_BY_EMAIL,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
            )
        except (OAuthProviderError, TokenError):
            raise OAUTH_ERROR_EXCEPTION

        for backend in fullauth.backends:
            await backend.write_token(response, token_pair.access_token)

        await fullauth.hooks.emit(
            "after_oauth_login", user=user, provider=provider, is_new_user=is_new_user
        )
        if is_new_user:
            await fullauth.hooks.emit("after_register", user=user)
            await fullauth.hooks.emit("after_oauth_register", user=user, user_info=user_info)

        if fullauth.config.INCLUDE_USER_IN_LOGIN and user:
            return LoginResponse(
                access_token=token_pair.access_token,
                refresh_token=token_pair.refresh_token,
                token_type=token_pair.token_type,
                expires_in=token_pair.expires_in,
                user=user,
            )

        return token_pair

    @router.get(
        "/oauth/accounts",
        status_code=200,
        response_model=list[OAuthAccountResponse],
        description="List OAuth accounts linked to the current user.",
    )
    async def list_oauth_accounts(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> list[OAuthAccountResponse]:
        accounts = await fullauth.adapter.get_user_oauth_accounts(user.id)
        return [
            OAuthAccountResponse(
                provider=a.provider,
                provider_user_id=a.provider_user_id,
                provider_email=a.provider_email,
            )
            for a in accounts
        ]

    @router.delete(
        "/oauth/accounts/{provider}",
        status_code=204,
        description="Unlink an OAuth provider from your account.",
    )
    async def unlink_oauth_account(
        provider: str,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> None:
        accounts = await fullauth.adapter.get_user_oauth_accounts(user.id)
        has_password = await fullauth.adapter.get_hashed_password(user.id) is not None
        other_oauth = [a for a in accounts if a.provider != provider]

        if not has_password and not other_oauth:
            raise HTTPException(
                status_code=400,
                detail="Cannot unlink the only login method. Set a password first.",
            )

        await fullauth.adapter.delete_oauth_account(provider, user.id)
        logger.info("OAuth account unlinked: user_id=%s, provider=%s", user.id, provider)

    return router
