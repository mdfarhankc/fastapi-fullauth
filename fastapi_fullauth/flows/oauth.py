import base64
import hashlib
import hmac
import logging
import secrets
from typing import Any, cast

from fastapi_fullauth.adapters.base import AbstractUserAdapter, OAuthAdapterMixin
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import (
    OAuthAccountAlreadyLinkedError,
    OAuthProviderAlreadyLinkedError,
    OAuthProviderError,
    UserAlreadyExistsError,
)
from fastapi_fullauth.flows.tokens import issue_token_pair
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import (
    OAuthAccount,
    OAuthUserInfo,
    TokenPair,
    TokenPayload,
    UserID,
    UserSchema,
)

logger = logging.getLogger("fastapi_fullauth.oauth")

# Purposes keep the two flows apart: a sign-in state cannot be redeemed at the
# link callback, and a link state cannot sign anyone in.
STATE_PURPOSE = "oauth_state"
LINK_STATE_PURPOSE = "oauth_link"

_RESERVED_STATE_CLAIMS = frozenset({"purpose", "nonce", "binding", "redirect_uri"})


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


def generate_oauth_binding() -> str:
    """Create the secret that binds an OAuth state to the client that started the flow.

    Return it to the client alongside the authorization URL. The client keeps it
    (sessionStorage for a SPA) and sends it back with the callback. The state only
    carries its hash, so a state an attacker obtained for their own login cannot
    be redeemed by a victim's browser, which never had the attacker's binding.
    RFC 9700 requires this binding of the ``state`` to the user agent.
    """
    return secrets.token_urlsafe(32)


def _binding_digest(binding: str) -> str:
    return _b64url(hashlib.sha256(binding.encode()).digest())


def generate_oauth_state(
    token_engine: TokenEngine,
    ttl_seconds: int = 300,
    redirect_uri: str | None = None,
    nonce: str | None = None,
    *,
    binding: str,
    purpose: str = STATE_PURPOSE,
    claims: dict[str, Any] | None = None,
) -> str:
    """Create the signed, user-agent-bound state token for an OAuth flow.

    ``claims`` are carried in the state and returned at the callback. The claims
    the state's own security rests on cannot be set this way.

    The subject is always ``"oauth-state"``, never a real user id: the state
    travels through the browser's address bar and the provider, so it must be
    worthless as a session token.
    """
    extra: dict[str, Any] = {
        k: v for k, v in (claims or {}).items() if k not in _RESERVED_STATE_CLAIMS
    }
    extra.update(
        {
            "purpose": purpose,
            "nonce": nonce or secrets.token_hex(16),
            "binding": _binding_digest(binding),
        }
    )
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
    *,
    binding: str,
    purpose: str = STATE_PURPOSE,
    claims: dict[str, Any] | None = None,
) -> str:
    """Create a signed state token and return the provider authorization URL.

    ``binding`` comes from :func:`generate_oauth_binding` and must be returned to
    the client, which presents it again at the callback.

    Adds a PKCE code_challenge when both ``pkce_enabled`` and the provider
    supports PKCE. The matching verifier is derived from the state nonce at
    token exchange, so nothing extra needs to be stored between requests.
    """
    nonce = secrets.token_hex(16)
    state = generate_oauth_state(
        token_engine,
        ttl_seconds,
        redirect_uri,
        nonce=nonce,
        binding=binding,
        purpose=purpose,
        claims=claims,
    )

    secret = token_engine.config.SECRET_KEY
    if pkce_enabled and provider.supports_pkce and secret:
        challenge = _pkce_code_challenge(_derive_pkce_verifier(secret, nonce))
        return provider.get_authorization_url(state, redirect_uri, code_challenge=challenge)
    return provider.get_authorization_url(state, redirect_uri)


def build_link_authorization_url(
    token_engine: TokenEngine,
    provider: OAuthProvider,
    redirect_uri: str,
    user_id: UserID,
    ttl_seconds: int = 300,
    pkce_enabled: bool = True,
    *,
    binding: str,
) -> str:
    """Authorization URL for attaching ``provider`` to an already-signed-in user.

    The state names the user it was issued for, which the callback checks against
    the caller's session. Without that check, an attacker could run this flow with
    their own provider account and have a victim submit the result, attaching the
    attacker's identity to the victim's account.
    """
    return build_authorization_url(
        token_engine,
        provider,
        redirect_uri,
        ttl_seconds,
        pkce_enabled,
        binding=binding,
        purpose=LINK_STATE_PURPOSE,
        claims={"link_user_id": str(user_id)},
    )


async def _decode_bound_state(
    token_engine: TokenEngine, state: str, binding: str, *, purpose: str = STATE_PURPOSE
) -> TokenPayload:
    payload = await token_engine.decode_token(state, expected_type="access")
    if payload.extra.get("purpose") != purpose:
        logger.warning("Invalid OAuth state token (wrong purpose)")
        raise OAuthProviderError("Invalid OAuth state token")
    expected = payload.extra.get("binding")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, _binding_digest(binding)):
        logger.warning("OAuth state rejected: not bound to the presenting client")
        raise OAuthProviderError("Invalid OAuth state token")
    return payload


async def verify_oauth_state(token_engine: TokenEngine, state: str, *, binding: str) -> str | None:
    payload = await _decode_bound_state(token_engine, state, binding)
    redirect_uri: str | None = payload.extra.get("redirect_uri")
    return redirect_uri


async def exchange_oauth_code(
    provider: OAuthProvider,
    token_engine: TokenEngine,
    code: str,
    state: str,
    pkce_enabled: bool = True,
    *,
    binding: str,
) -> tuple[dict[str, Any], OAuthUserInfo]:
    """Verify the state and its binding, then exchange the code for user info."""
    # Checked before the state is burned, so a mismatched attempt cannot use up
    # the legitimate client's state.
    payload = await _decode_bound_state(token_engine, state, binding)
    return await _burn_state_and_exchange(provider, token_engine, payload, code, pkce_enabled)


async def _burn_state_and_exchange(
    provider: OAuthProvider,
    token_engine: TokenEngine,
    payload: TokenPayload,
    code: str,
    pkce_enabled: bool,
) -> tuple[dict[str, Any], OAuthUserInfo]:
    """Consume an already-verified state, then exchange the code for user info."""
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


def _ensure_active(user: UserSchema) -> None:
    # Checked before any write, so a deactivated account gains no provider link
    # and no refreshed provider tokens from a refused sign-in.
    if not user.is_active:
        logger.warning("OAuth login blocked; account deactivated: user_id=%s", user.id)
        raise OAuthProviderError("User account is deactivated")


async def _ensure_provider_not_linked(
    oauth_adapter: "OAuthAdapterMixin", user: UserSchema, info: OAuthUserInfo
) -> None:
    """Refuse a second identity from the same provider on one account.

    Unlinking resolves by provider alone, so a duplicate row would leave the
    provider attached after the user unlinked it, with no way to reach the
    leftover. Reachable when two accounts at one provider verify the same email.
    """
    for account in await oauth_adapter.get_user_oauth_accounts(user.id):
        if account.provider == info.provider:
            logger.warning(
                "oauth auto-link refused: account already linked to %s (user_id=%s, "
                "existing=%s, attempted=%s)",
                info.provider,
                user.id,
                account.provider_user_id,
                info.provider_user_id,
            )
            raise OAuthProviderAlreadyLinkedError(
                f"Your account is already linked to a different {info.provider} account."
            )


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
        _ensure_active(user)

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
                    "This email is already registered. Sign in with your password, "
                    f"then link your {info.provider} account."
                )
            _ensure_active(existing)
            await _ensure_provider_not_linked(oauth_adapter, existing, info)
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
    *,
    binding: str,
) -> tuple[TokenPair, UserSchema, bool, OAuthUserInfo]:
    """Full OAuth callback flow. Delegates to smaller functions."""
    provider_tokens, info = await exchange_oauth_code(
        provider, token_engine, code, state, pkce_enabled=pkce_enabled, binding=binding
    )

    user, is_new_user = await link_or_create_user(
        adapter, info, provider_tokens, auto_link_by_email
    )

    # Parity with the password (login.py) and passkey flows: a deactivated user
    # must not be able to sign in, including through a linked social account.
    if not user.is_active:
        logger.warning("OAuth login blocked; account deactivated: user_id=%s", user.id)
        raise OAuthProviderError("User account is deactivated")

    if is_new_user:
        logger.info("OAuth user created: provider=%s, email=%s", info.provider, info.email)
    else:
        logger.info("OAuth login: provider=%s, user_id=%s", info.provider, user.id)

    token_pair = await issue_oauth_tokens(
        adapter, token_engine, user, user_agent=user_agent, ip_address=ip_address
    )

    return token_pair, user, is_new_user, info


async def link_oauth_account(
    adapter: AbstractUserAdapter,
    user: UserSchema,
    info: OAuthUserInfo,
    provider_tokens: dict[str, Any],
) -> OAuthAccount:
    """Attach a provider identity to an already-authenticated user.

    Authorization comes from the caller's session, so the provider email is
    stored for display only: it is never matched against an account, and the user
    row, including ``is_verified``, is left untouched.

    Raises :class:`OAuthAccountAlreadyLinkedError` rather than moving an identity
    that belongs to another user, and :class:`OAuthProviderAlreadyLinkedError`
    when the user already linked a different account from the same provider,
    which unlinking (keyed by provider alone) could not tell apart.
    """
    oauth_adapter = cast("OAuthAdapterMixin", adapter)
    fields: dict[str, Any] = {
        "access_token": provider_tokens.get("access_token"),
        "refresh_token": provider_tokens.get("refresh_token"),
        "provider_email": info.email,
    }

    existing = await oauth_adapter.get_oauth_account(info.provider, info.provider_user_id)
    if existing is not None:
        if existing.user_id == user.id:
            updated = await oauth_adapter.update_oauth_account(
                info.provider, info.provider_user_id, fields
            )
            logger.info("OAuth account re-linked: user_id=%s, provider=%s", user.id, info.provider)
            return updated or existing.model_copy(update=fields)

        owner = await adapter.get_user_by_id(existing.user_id)
        if owner is not None:
            logger.warning(
                "OAuth link refused: identity owned by another user "
                "(provider=%s, provider_user_id=%s, requested_by=%s)",
                info.provider,
                info.provider_user_id,
                user.id,
            )
            raise OAuthAccountAlreadyLinkedError(
                f"This {info.provider} account is already linked to another user."
            )

        # The owner is gone but the row outlived it (storage without cascading
        # deletes). Leaving it would block the identity forever.
        logger.warning(
            "Replacing an orphaned OAuth link: provider=%s, provider_user_id=%s",
            info.provider,
            info.provider_user_id,
        )
        await oauth_adapter.delete_oauth_account(info.provider, info.provider_user_id)

    for account in await oauth_adapter.get_user_oauth_accounts(user.id):
        if account.provider == info.provider:
            logger.info(
                "OAuth link refused: provider already linked (user_id=%s, provider=%s)",
                user.id,
                info.provider,
            )
            raise OAuthProviderAlreadyLinkedError(
                f"Your account is already linked to a different {info.provider} account."
            )

    created = await oauth_adapter.create_oauth_account(
        OAuthAccount(
            provider=info.provider,
            provider_user_id=info.provider_user_id,
            user_id=user.id,
            provider_email=info.email,
            access_token=provider_tokens.get("access_token"),
            refresh_token=provider_tokens.get("refresh_token"),
        )
    )
    if created.user_id != user.id:
        # The adapters treat a duplicate insert as success and return the row
        # that won, which on a race is another account's. Reporting that as a
        # successful link would tell the caller they own an identity they do not.
        logger.warning(
            "OAuth link lost a race to another account (provider=%s, provider_user_id=%s, "
            "requested_by=%s)",
            info.provider,
            info.provider_user_id,
            user.id,
        )
        raise OAuthAccountAlreadyLinkedError(
            f"This {info.provider} account is already linked to another user."
        )
    logger.info("OAuth account linked: user_id=%s, provider=%s", user.id, info.provider)
    return created


async def oauth_link_callback(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    provider: OAuthProvider,
    code: str,
    state: str,
    user: UserSchema,
    pkce_enabled: bool = True,
    *,
    binding: str,
) -> OAuthAccount:
    """Finish a link flow: verify the state, exchange the code, attach the identity.

    Issues no tokens. The caller is already signed in, and linking a provider is
    not a sign-in.
    """
    # Both checks run before the state is burned and before the code is spent, so
    # a rejected attempt cannot consume the legitimate client's state.
    payload = await _decode_bound_state(token_engine, state, binding, purpose=LINK_STATE_PURPOSE)
    issued_for = payload.extra.get("link_user_id")
    if not isinstance(issued_for, str) or issued_for != str(user.id):
        logger.warning(
            "OAuth link state rejected: issued for another user (provider=%s, presented_by=%s)",
            provider.name,
            user.id,
        )
        raise OAuthProviderError("Invalid OAuth state token")

    provider_tokens, info = await _burn_state_and_exchange(
        provider, token_engine, payload, code, pkce_enabled
    )
    return await link_oauth_account(adapter, user, info, provider_tokens)
