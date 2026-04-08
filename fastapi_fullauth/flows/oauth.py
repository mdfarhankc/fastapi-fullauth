import secrets

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import OAuthProviderError
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthAccount, OAuthUserInfo, RefreshToken, TokenPair, UserSchema


def generate_oauth_state(token_engine: TokenEngine, ttl_seconds: int = 300) -> str:
    return token_engine.create_access_token(
        user_id="oauth-state",
        extra={"purpose": "oauth_state", "nonce": secrets.token_hex(16)},
    )


async def verify_oauth_state(token_engine: TokenEngine, state: str) -> None:
    payload = await token_engine.decode_token(state)
    if payload.extra.get("purpose") != "oauth_state":
        raise OAuthProviderError("Invalid OAuth state token")


async def oauth_callback(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    provider: OAuthProvider,
    code: str,
    state: str,
    auto_link_by_email: bool = True,
) -> tuple[TokenPair, UserSchema, bool]:
    await verify_oauth_state(token_engine, state)

    tokens = await provider.exchange_code(code)
    info: OAuthUserInfo = await provider.get_user_info(tokens)

    # check if this provider account is already linked
    existing_account = await adapter.get_oauth_account(info.provider, info.provider_user_id)

    if existing_account:
        # returning user — update stored tokens
        user = await adapter.get_user_by_id(existing_account.user_id)
        if user is None:
            raise OAuthProviderError("Linked user no longer exists")

        await adapter.update_oauth_account(
            info.provider,
            info.provider_user_id,
            {
                "access_token": tokens.get("access_token"),
                "refresh_token": tokens.get("refresh_token"),
                "provider_email": info.email,
            },
        )
        is_new_user = False
    else:
        # new provider link — check if email already has an account
        user = None
        if info.email and auto_link_by_email:
            user = await adapter.get_user_by_email(info.email)

        if user is None:
            # create new user with random password
            from fastapi_fullauth.types import CreateUserSchema

            if not info.email:
                raise OAuthProviderError(
                    f"No email returned from {info.provider}. Cannot create account."
                )

            random_password = secrets.token_urlsafe(32)
            data = CreateUserSchema(email=info.email, password=random_password)
            user = await adapter.create_user(data, hashed_password=hash_password(random_password))

            if info.email_verified:
                await adapter.set_user_verified(str(user.id))
                user = user.model_copy(update={"is_verified": True})

            is_new_user = True
        else:
            is_new_user = False

        # link the OAuth account
        await adapter.create_oauth_account(
            OAuthAccount(
                provider=info.provider,
                provider_user_id=info.provider_user_id,
                user_id=str(user.id),
                provider_email=info.email,
                access_token=tokens.get("access_token"),
                refresh_token=tokens.get("refresh_token"),
            )
        )

    # issue our JWT tokens
    roles = await adapter.get_user_roles(str(user.id))
    access, refresh_meta = token_engine.create_token_pair(
        user_id=str(user.id),
        roles=roles,
    )

    await adapter.store_refresh_token(
        RefreshToken(
            token=refresh_meta.token,
            user_id=str(user.id),
            expires_at=refresh_meta.expires_at,
            family_id=refresh_meta.family_id,
        )
    )

    token_pair = TokenPair(
        access_token=access,
        refresh_token=refresh_meta.token,
        expires_in=token_engine.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return token_pair, user, is_new_user
