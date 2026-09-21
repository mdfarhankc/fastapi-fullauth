import logging
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from fastapi_fullauth.adapters.base import OAuthAdapterMixin
from fastapi_fullauth.dependencies.current_user import CurrentUser, get_fullauth
from fastapi_fullauth.exceptions import (
    OAUTH_ERROR_EXCEPTION,
    OAuthAccountAlreadyLinkedError,
    OAuthError,
    OAuthProviderAlreadyLinkedError,
    TokenError,
)
from fastapi_fullauth.flows.credentials import last_method_detail, remaining_login_methods
from fastapi_fullauth.flows.oauth import (
    build_authorization_url,
    build_link_authorization_url,
    generate_oauth_binding,
    oauth_callback,
    oauth_link_callback,
)
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.routers._schemas import LoginResponse, build_login_response_model
from fastapi_fullauth.routers._transport import write_tokens
from fastapi_fullauth.types import TokenPair, UserSchema, UserSchemaType
from fastapi_fullauth.utils import request_session_metadata

logger = logging.getLogger("fastapi_fullauth.oauth")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str
    binding: str = Field(
        min_length=1,
        max_length=512,
        description="The `binding` returned by the authorize endpoint that started this flow.",
    )


class OAuthProviderListResponse(BaseModel):
    providers: list[str]


class OAuthAuthorizeResponse(BaseModel):
    authorization_url: str
    binding: str = Field(
        description=(
            "Secret binding this login attempt to your client. Keep it (for example in "
            "sessionStorage) and send it back with the callback. Never put it in a URL."
        ),
    )


class OAuthAccountResponse(BaseModel):
    provider: str
    provider_user_id: str
    provider_email: str | None = None


def _require_oauth_adapter(fullauth: "FullAuth") -> None:
    """The combined router only mounts these when the adapter supports OAuth, but
    the routers are composable: mounted by hand, the adapter's RuntimeError would
    surface as a 500."""
    if not fullauth.adapter.supports_feature("oauth"):
        raise HTTPException(status_code=501, detail="Adapter does not support OAuth")


def _require_provider(fullauth: "FullAuth", provider: str) -> OAuthProvider:
    oauth_provider = fullauth.oauth_providers.get(provider)
    if oauth_provider is None:
        raise HTTPException(status_code=404, detail=f"OAuth provider '{provider}' not configured")
    return oauth_provider


def create_oauth_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
    login_response_schema: type[LoginResponse] = LoginResponse,
) -> APIRouter:
    LoginResponse = build_login_response_model(user_schema, base=login_response_schema)  # noqa: N806
    router = APIRouter()

    @router.get(
        "/oauth/providers",
        status_code=200,
        response_model=OAuthProviderListResponse,
        description="List configured OAuth providers.",
    )
    async def list_providers(
        fullauth: "FullAuth" = Depends(get_fullauth),
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
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> OAuthAuthorizeResponse:
        oauth_provider = _require_provider(fullauth, provider)
        if redirect_uri not in oauth_provider.redirect_uris:
            raise HTTPException(status_code=400, detail="Invalid redirect URI")

        binding = generate_oauth_binding()
        url = build_authorization_url(
            fullauth.token_engine,
            oauth_provider,
            redirect_uri,
            ttl_seconds=fullauth.config.OAUTH_STATE_EXPIRE_SECONDS,
            pkce_enabled=fullauth.config.OAUTH_PKCE_ENABLED,
            binding=binding,
        )
        return OAuthAuthorizeResponse(authorization_url=url, binding=binding)

    @router.post(
        "/oauth/{provider}/callback",
        status_code=200,
        response_model=LoginResponse,
        description="Exchange OAuth authorization code for tokens.",
    )
    async def callback(
        provider: str,
        data: OAuthCallbackRequest,
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> TokenPair:
        await fullauth.enforce_rate_limit(request, "login")

        oauth_provider = _require_provider(fullauth, provider)
        user_agent, ip_address = request_session_metadata(
            request, fullauth.config.TRUSTED_PROXY_HEADERS, fullauth.config.TRUSTED_PROXY_COUNT
        )

        try:
            token_pair, user, is_new_user, user_info = await oauth_callback(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                provider=oauth_provider,
                code=data.code,
                state=data.state,
                auto_link_by_email=fullauth.config.OAUTH_AUTO_LINK_BY_EMAIL,
                pkce_enabled=fullauth.config.OAUTH_PKCE_ENABLED,
                user_agent=user_agent,
                ip_address=ip_address,
                binding=data.binding,
            )
        except (OAuthError, TokenError):
            raise OAUTH_ERROR_EXCEPTION

        token_pair = await write_tokens(response, fullauth, token_pair)

        await fullauth.hooks.emit(
            "after_oauth_login", user=user, provider=provider, is_new_user=is_new_user
        )
        if is_new_user:
            await fullauth.hooks.emit("after_register", user=user)
            await fullauth.hooks.emit("after_oauth_register", user=user, user_info=user_info)

        if user is not None:
            return LoginResponse(
                access_token=token_pair.access_token,
                refresh_token=token_pair.refresh_token,
                token_type=token_pair.token_type,
                expires_in=token_pair.expires_in,
                user=user,
            )

        return token_pair

    @router.get(
        "/oauth/{provider}/link/authorize",
        status_code=200,
        response_model=OAuthAuthorizeResponse,
        description="Get the authorization URL for linking a provider to the signed-in account.",
    )
    async def link_authorize(
        provider: str,
        redirect_uri: str,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> OAuthAuthorizeResponse:
        _require_oauth_adapter(fullauth)
        oauth_provider = _require_provider(fullauth, provider)
        if redirect_uri not in oauth_provider.redirect_uris:
            raise HTTPException(status_code=400, detail="Invalid redirect URI")

        binding = generate_oauth_binding()
        url = build_link_authorization_url(
            fullauth.token_engine,
            oauth_provider,
            redirect_uri,
            user.id,
            ttl_seconds=fullauth.config.OAUTH_STATE_EXPIRE_SECONDS,
            pkce_enabled=fullauth.config.OAUTH_PKCE_ENABLED,
            binding=binding,
        )
        return OAuthAuthorizeResponse(authorization_url=url, binding=binding)

    @router.post(
        "/oauth/{provider}/link/callback",
        status_code=200,
        response_model=OAuthAccountResponse,
        description="Link the provider account from this flow to the signed-in account.",
    )
    async def link_callback(
        provider: str,
        data: OAuthCallbackRequest,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> OAuthAccountResponse:
        _require_oauth_adapter(fullauth)
        oauth_provider = _require_provider(fullauth, provider)

        # Unlike sign-in, this route answers with the specific reason: the caller
        # is authenticated, so there is nothing to enumerate, and a settings
        # screen has to tell the two conflicts apart.
        try:
            account = await oauth_link_callback(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                provider=oauth_provider,
                code=data.code,
                state=data.state,
                user=user,
                pkce_enabled=fullauth.config.OAUTH_PKCE_ENABLED,
                binding=data.binding,
            )
        except (OAuthAccountAlreadyLinkedError, OAuthProviderAlreadyLinkedError) as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        except (OAuthError, TokenError):
            raise OAUTH_ERROR_EXCEPTION

        await fullauth.hooks.emit("after_oauth_link", user=user, provider=provider)
        return OAuthAccountResponse(
            provider=account.provider,
            provider_user_id=account.provider_user_id,
            provider_email=account.provider_email,
        )

    @router.get(
        "/oauth/accounts",
        status_code=200,
        response_model=list[OAuthAccountResponse],
        description="List OAuth accounts linked to the current user.",
    )
    async def list_oauth_accounts(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> list[OAuthAccountResponse]:
        _require_oauth_adapter(fullauth)
        adapter = cast("OAuthAdapterMixin", fullauth.adapter)
        accounts = await adapter.get_user_oauth_accounts(user.id)
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
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> None:
        _require_oauth_adapter(fullauth)
        oauth_adapter = cast("OAuthAdapterMixin", fullauth.adapter)
        accounts = await oauth_adapter.get_user_oauth_accounts(user.id)

        target = next((a for a in accounts if a.provider == provider), None)
        if target is None:
            raise HTTPException(status_code=404, detail="OAuth account not found")

        # Passkeys count as a sign-in method here, so a passwordless user with a
        # passkey is not told to set a password they do not need.
        passkeys_usable = fullauth.config.PASSKEY_ENABLED and fullauth.adapter.supports_feature(
            "passkey"
        )
        if not await remaining_login_methods(
            fullauth.adapter,
            user.id,
            usable_providers=set(fullauth.oauth_providers),
            passkeys_usable=passkeys_usable,
            without_provider=provider,
        ):
            raise HTTPException(
                status_code=400,
                detail=last_method_detail(passkeys_available=passkeys_usable),
            )

        await oauth_adapter.delete_oauth_account(provider, target.provider_user_id)
        logger.info("OAuth account unlinked: user_id=%s, provider=%s", user.id, provider)
        await fullauth.hooks.emit("after_oauth_unlink", user=user, provider=provider)

    return router
