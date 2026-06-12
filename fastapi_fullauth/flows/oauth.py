import base64
import hashlib
import hmac
import logging
import secrets
from typing import Any, cast

from fastapi_fullauth.adapters.base import AbstractUserAdapter, OAuthAdapterMixin
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import OAuthProviderError, UserAlreadyExistsError
from fastapi_fullauth.flows.tokens import issue_token_pair
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthAccount, OAuthUserInfo, TokenPair, UserSchema

logger = logging.getLogger("fastapi_fullauth.oauth")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _derive_pkce_verifier(secret_key: str, nonce: str) -> str:
    """Derive a PKCE code_verifier from the signing secret and state nonce.

    The verifier never travels through the browser: it is recomputed at token
    exchange from the nonce carried in the signed state token. This keeps the
    OAuth flow stateless (no server-side verifier storage) while keeping the
    verifier secret from anyone who only sees the front-channel redirect.
    """
    digest = hmac.new(secret_key.encode(), f"pkce:{nonce}".encode(), hashlib.sha256).digest()
    return _b64url(digest)


def _pkce_code_challenge(verifier: str) -> str:
    """S256 transform: base64url(sha256(verifier))."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def generate_oauth_state(
    token_engine: TokenEngine,
    ttl_seconds: int = 300,
    redirect_uri: str | None = None,
    nonce: str | None = None,
) -> str:
    extra: dict[str, Any] = {"purpose": "oauth_state", "nonce": nonce or secrets.token_hex(16)}
    if redirect_uri:
        extra["redirect_uri"] = redirect_uri
    return token_engine.create_access_token(
        user_id="oauth-state", extra=extra, expire_seconds=ttl_seconds
    )


def build_authorization_url(
    token_engine: TokenEngine,
    provider: OAuthProvider,
    redirect_uri: str,
    ttl_seconds: int = 300,
    pkce_enabled: bool = True,
) -> str:
    """Create a signed state token and return the provider authorization URL.

    Adds a PKCE code_challenge when both ``pkce_enabled`` and the provider
    supports PKCE. The matching verifier is derived from the state nonce at
    token exchange, so nothing extra needs to be stored between requests.
    """
    nonce = secrets.token_hex(16)
    state = generate_oauth_state(token_engine, ttl_seconds, redirect_uri, nonce=nonce)

    secret = token_engine.config.SECRET_KEY
    if pkce_enabled and provider.supports_pkce and secret:
        challenge = _pkce_code_challenge(_derive_pkce_verifier(secret, nonce))
        return provider.get_authorization_url(state, redirect_uri, code_challenge=challenge)
    return provider.get_authorization_url(state, redirect_uri)


async def verify_oauth_state(token_engine: TokenEngine, state: str) -> str | None:
    payload = await token_engine.decode_token(state, expected_type="access")
    if payload.extra.get("purpose") != "oauth_state":
        logger.warning("Invalid OAuth state token (wrong purpose)")
        raise OAuthProviderError("Invalid OAuth state token")
    redirect_uri: str | None = payload.extra.get("redirect_uri")
    return redirect_uri


async def exchange_oauth_code(
    provider: OAuthProvider,
    token_engine: TokenEngine,
    code: str,
    state: str,
    pkce_enabled: bool = True,
) -> tuple[dict[str, Any], OAuthUserInfo]:
    """Verify state and exchange authorization code for user info."""
    payload = await token_engine.decode_token(state, expected_type="access")
    if payload.extra.get("purpose") != "oauth_state":
        logger.warning("Invalid OAuth state token (wrong purpose)")
        raise OAuthProviderError("Invalid OAuth state token")

    # Single-use: burn the state so a captured (code, state) pair can't be
    # replayed within the state's TTL. Decoding it again raises TokenBlacklisted.
    if token_engine.config.BLACKLIST_ENABLED:
        await token_engine.blacklist_payload(payload)

    redirect_uri = payload.extra.get("redirect_uri") or provider.redirect_uris[0]

    secret = token_engine.config.SECRET_KEY
    code_verifier: str | None = None
    if pkce_enabled and provider.supports_pkce and secret:
        nonce = payload.extra.get("nonce")
        if nonce:
            code_verifier = _derive_pkce_verifier(secret, nonce)

    if code_verifier is not None:
        tokens = await provider.exchange_code(code, redirect_uri, code_verifier=code_verifier)
    else:
        tokens = await provider.exchange_code(code, redirect_uri)
    info: OAuthUserInfo = await provider.get_user_info(tokens)
    return tokens, info


async def link_or_create_user(
    adapter: AbstractUserAdapter,
    info: OAuthUserInfo,
    provider_tokens: dict[str, Any],
    auto_link_by_email: bool = True,
) -> tuple[UserSchema, bool]:
    """Link OAuth account to existing user or create a new one.

    Returns the user and whether a new account was created.
    """
    oauth_adapter = cast("OAuthAdapterMixin", adapter)
    existing_account = await oauth_adapter.get_oauth_account(info.provider, info.provider_user_id)

    if existing_account:
        user = await adapter.get_user_by_id(existing_account.user_id)
        if user is None:
            logger.error(
                "OAuth linked user missing: provider=%s, provider_user_id=%s",
                info.provider,
                info.provider_user_id,
            )
            raise OAuthProviderError("Linked user no longer exists")

        await oauth_adapter.update_oauth_account(
            info.provider,
            info.provider_user_id,
            {
                "access_token": provider_tokens.get("access_token"),
                "refresh_token": provider_tokens.get("refresh_token"),
                "provider_email": info.email,
            },
        )
        return user, False

    # new provider link; check if email already has an account
    user = None
    if info.email and auto_link_by_email:
        existing = await adapter.get_user_by_email(info.email)
        if existing is not None:
            # Only auto-link when the provider confirms email ownership; otherwise
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

        # OAuth users have no password; they auth via the provider. CreateUserSchema
        # still requires `password`, but hashed_password=None means it's never persisted.
        data = CreateUserSchema(email=info.email, password=secrets.token_urlsafe(32))
        try:
            user = await adapter.create_user(data, hashed_password=None)
        except UserAlreadyExistsError as e:
            # Lost a race against a concurrent local signup (or another OAuth flow).
            # Ask the user to retry; the next attempt will find the now-existing account.
            logger.warning(
                "oauth signup lost a race to concurrent registration (provider=%s)",
                info.provider,
            )
            raise OAuthProviderError("Please retry signing in.") from e

        if info.email_verified:
            await adapter.set_user_verified(user.id)
            user = user.model_copy(update={"is_verified": True})

        is_new_user = True
    else:
        is_new_user = False

    await oauth_adapter.create_oauth_account(
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
    *,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> TokenPair:
    """Issue JWT token pair for an OAuth-authenticated user."""
    return await issue_token_pair(
        adapter, token_engine, user, user_agent=user_agent, ip_address=ip_address
    )


async def oauth_callback(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    provider: OAuthProvider,
    code: str,
    state: str,
    auto_link_by_email: bool = True,
    pkce_enabled: bool = True,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> tuple[TokenPair, UserSchema, bool, OAuthUserInfo]:
    """Full OAuth callback flow. Delegates to smaller functions."""
    provider_tokens, info = await exchange_oauth_code(
        provider, token_engine, code, state, pkce_enabled=pkce_enabled
    )

    user, is_new_user = await link_or_create_user(
        adapter, info, provider_tokens, auto_link_by_email
    )

    if is_new_user:
        logger.info("OAuth user created: provider=%s, email=%s", info.provider, info.email)
    else:
        logger.info("OAuth login: provider=%s, user_id=%s", info.provider, user.id)

    token_pair = await issue_oauth_tokens(
        adapter, token_engine, user, user_agent=user_agent, ip_address=ip_address
    )

    return token_pair, user, is_new_user, info
