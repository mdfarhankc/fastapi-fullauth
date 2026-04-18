import logging
import secrets

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import OAuthProviderError, UserAlreadyExistsError
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthAccount, OAuthUserInfo, RefreshToken, TokenPair, UserSchema

logger = logging.getLogger("fastapi_fullauth.oauth")


def generate_oauth_state(
    token_engine: TokenEngine,
    ttl_seconds: int = 300,
    redirect_uri: str | None = None,
) -> str:
    extra: dict = {"purpose": "oauth_state", "nonce": secrets.token_hex(16)}
    if redirect_uri:
        extra["redirect_uri"] = redirect_uri
    return token_engine.create_access_token(
        user_id="oauth-state", extra=extra, expire_seconds=ttl_seconds
    )


async def verify_oauth_state(token_engine: TokenEngine, state: str) -> str | None:
    payload = await token_engine.decode_token(state)
    if payload.extra.get("purpose") != "oauth_state":
        logger.warning("Invalid OAuth state token (wrong purpose)")
        raise OAuthProviderError("Invalid OAuth state token")
    return payload.extra.get("redirect_uri")


async def exchange_oauth_code(
    provider: OAuthProvider,
    token_engine: TokenEngine,
    code: str,
    state: str,
) -> tuple[dict, OAuthUserInfo]:
    """Verify state and exchange authorization code for user info."""
    redirect_uri = await verify_oauth_state(token_engine, state)
    tokens = await provider.exchange_code(code, redirect_uri)
    info: OAuthUserInfo = await provider.get_user_info(tokens)
    return tokens, info


async def link_or_create_user(
    adapter: AbstractUserAdapter,
    info: OAuthUserInfo,
    provider_tokens: dict,
    auto_link_by_email: bool = True,
    hash_algorithm: str = "argon2id",
) -> tuple[UserSchema, bool]:
    """Link OAuth account to existing user or create a new one.

    Returns the user and whether a new account was created.
    """
    existing_account = await adapter.get_oauth_account(info.provider, info.provider_user_id)

    if existing_account:
        user = await adapter.get_user_by_id(existing_account.user_id)
        if user is None:
            logger.error(
                "OAuth linked user missing: provider=%s, provider_user_id=%s",
                info.provider,
                info.provider_user_id,
            )
            raise OAuthProviderError("Linked user no longer exists")

        await adapter.update_oauth_account(
            info.provider,
            info.provider_user_id,
            {
                "access_token": provider_tokens.get("access_token"),
                "refresh_token": provider_tokens.get("refresh_token"),
                "provider_email": info.email,
            },
        )
        return user, False

    # new provider link — check if email already has an account
    user = None
    if info.email and auto_link_by_email:
        existing = await adapter.get_user_by_email(info.email)
        if existing is not None:
            # Only auto-link when the provider confirms email ownership — otherwise
            # anyone who signs up at the provider with a victim's email takes the account.
            if not info.email_verified:
                logger.warning(
                    "oauth auto-link refused: unverified email on existing account "
                    "(provider=%s, provider_user_id=%s)",
                    info.provider,
                    info.provider_user_id,
                )
                raise OAuthProviderError(
                    "This email is already registered. Sign in with your existing "
                    "credentials and link your OAuth account from account settings."
                )
            user = existing

    if user is None:
        from fastapi_fullauth.types import CreateUserSchema

        if not info.email:
            logger.error("OAuth provider returned no email: %s", info.provider)
            raise OAuthProviderError(
                f"No email returned from {info.provider}. Cannot create account."
            )

        random_password = secrets.token_urlsafe(32)
        data = CreateUserSchema(email=info.email, password=random_password)
        try:
            user = await adapter.create_user(
                data, hashed_password=hash_password(random_password, algorithm=hash_algorithm)
            )
        except UserAlreadyExistsError as e:
            # Lost a race against a concurrent local signup (or another OAuth flow).
            # Ask the user to retry — the next attempt will find the now-existing account.
            logger.warning(
                "oauth signup lost a race to concurrent registration (provider=%s)",
                info.provider,
            )
            raise OAuthProviderError("Please retry signing in.") from e
        await adapter.update_user(user.id, {"has_usable_password": False})

        if info.email_verified:
            await adapter.set_user_verified(user.id)
            user = user.model_copy(update={"is_verified": True})

        is_new_user = True
    else:
        is_new_user = False

    await adapter.create_oauth_account(
        OAuthAccount(
            provider=info.provider,
            provider_user_id=info.provider_user_id,
            user_id=user.id,
            provider_email=info.email,
            access_token=provider_tokens.get("access_token"),
            refresh_token=provider_tokens.get("refresh_token"),
        )
    )

    return user, is_new_user


async def issue_oauth_tokens(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    user: UserSchema,
) -> TokenPair:
    """Issue JWT token pair for an OAuth-authenticated user."""
    uid = str(user.id)
    roles = await adapter.get_user_roles(user.id)
    access, refresh_meta = token_engine.create_token_pair(user_id=uid, roles=roles)

    await adapter.store_refresh_token(
        RefreshToken(
            token=refresh_meta.token,
            user_id=uid,
            expires_at=refresh_meta.expires_at,
            family_id=refresh_meta.family_id,
        )
    )

    return TokenPair(
        access_token=access,
        refresh_token=refresh_meta.token,
        expires_in=token_engine.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def oauth_callback(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    provider: OAuthProvider,
    code: str,
    state: str,
    auto_link_by_email: bool = True,
    hash_algorithm: str = "argon2id",
) -> tuple[TokenPair, UserSchema, bool, OAuthUserInfo]:
    """Full OAuth callback flow. Delegates to smaller functions."""
    provider_tokens, info = await exchange_oauth_code(provider, token_engine, code, state)

    user, is_new_user = await link_or_create_user(
        adapter, info, provider_tokens, auto_link_by_email, hash_algorithm
    )

    if is_new_user:
        logger.info("OAuth user created: provider=%s, email=%s", info.provider, info.email)
    else:
        logger.info("OAuth login: provider=%s, user_id=%s", info.provider, user.id)

    token_pair = await issue_oauth_tokens(adapter, token_engine, user)

    return token_pair, user, is_new_user, info
