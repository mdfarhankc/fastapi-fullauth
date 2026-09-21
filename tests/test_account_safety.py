"""Keeping an account reachable and destructive actions deliberate.

Covers the rules that decide whether a credential may be removed, whether a
caller has proved they are present, and the hygiene around long-lived tokens.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import (
    CreateUserSchema,
    OAuthAccount,
    OAuthUserInfo,
    PasskeyCredential,
)

SECRET = "test-secret-key-that-is-long-enough-32b"


def _passkey(user_id, credential_id="cred-1") -> PasskeyCredential:
    return PasskeyCredential(
        id=uuid4(),
        user_id=user_id,
        credential_id=credential_id,
        public_key="key",
        device_name="Laptop",
    )


class _Provider(OAuthProvider):
    """Present only so the OAuth routes mount; no flow runs through it here."""

    name = "google"

    def __init__(self) -> None:
        self.client_id = "id"
        self.client_secret = "secret"
        self.redirect_uris = ["http://localhost/callback"]
        self.scopes = self.default_scopes

    @property
    def default_scopes(self) -> list[str]:
        return ["email"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        return "https://provider.test/auth"

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        raise NotImplementedError

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        raise NotImplementedError


def _oauth(user_id, provider="google") -> OAuthAccount:
    return OAuthAccount(provider=provider, provider_user_id="p-1", user_id=user_id)


@pytest.fixture
def passkey_config():
    return FullAuthConfig(
        SECRET_KEY=SECRET,
        PREVENT_REGISTRATION_ENUMERATION=False,
        PREVENT_LOGIN_TIMING_ATTACKS=False,
        PASSKEY_RP_ID="localhost",
        PASSKEY_ORIGINS=["http://localhost"],
    )


def _app(config, adapter, *, providers=None):
    fullauth = FullAuth(config=config, adapter=adapter, providers=providers)
    app = FastAPI()
    fullauth.init_app(app)
    return app, fullauth


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _passwordless_user(adapter, email="oauth-only@test.com"):
    return await adapter.create_user(
        CreateUserSchema(email=email, password="unused-securepass123"),
        hashed_password=None,
    )


def _headers(fullauth, user, *, auth_age_seconds: int = 0):
    """A real session token whose credentials were checked `auth_age_seconds` ago."""
    token = fullauth.token_engine.create_access_token(
        user_id=str(user.id),
        auth_time=datetime.now(timezone.utc) - timedelta(seconds=auth_age_seconds),
    )
    return {"Authorization": f"Bearer {token}"}


# ── Removing a sign-in method ────────────────────────────────────────


@pytest.mark.asyncio
async def test_unlinking_oauth_counts_a_passkey_as_a_way_back_in(passkey_config, adapter):
    """A passwordless user with a passkey does not need a password to unlink."""
    app, fullauth = _app(passkey_config, adapter, providers=[_Provider()])
    user = await _passwordless_user(adapter)
    await adapter.create_oauth_account(_oauth(user.id))
    await adapter.store_passkey(_passkey(user.id))

    async with _client(app) as client:
        r = await client.delete(
            "/api/v1/auth/oauth/accounts/google", headers=_headers(fullauth, user)
        )
        assert r.status_code == 204
        assert await adapter.get_user_oauth_accounts(user.id) == []


@pytest.mark.asyncio
async def test_unlinking_the_only_oauth_account_is_refused(passkey_config, adapter):
    app, fullauth = _app(passkey_config, adapter, providers=[_Provider()])
    user = await _passwordless_user(adapter)
    await adapter.create_oauth_account(_oauth(user.id))

    async with _client(app) as client:
        r = await client.delete(
            "/api/v1/auth/oauth/accounts/google", headers=_headers(fullauth, user)
        )
        assert r.status_code == 400
        assert "only sign-in method" in r.json()["detail"]
        # The message names passkeys only where they are available.
        assert "passkey" in r.json()["detail"]
        assert len(await adapter.get_user_oauth_accounts(user.id)) == 1


@pytest.mark.asyncio
async def test_deleting_the_only_passkey_is_refused(passkey_config, adapter):
    """The mirror of the unlink rule: a passkey-only account must not be able to
    delete its way out of existence."""
    app, fullauth = _app(passkey_config, adapter)
    user = await _passwordless_user(adapter)
    passkey = await adapter.store_passkey(_passkey(user.id))

    async with _client(app) as client:
        r = await client.delete(
            f"/api/v1/auth/passkeys/{passkey.id}", headers=_headers(fullauth, user)
        )
        assert r.status_code == 400
        assert "only sign-in method" in r.json()["detail"]
        assert len(await adapter.get_user_passkeys(user.id)) == 1


@pytest.mark.asyncio
async def test_deleting_a_passkey_is_allowed_when_a_password_remains(passkey_config, adapter):
    app, fullauth = _app(passkey_config, adapter)
    user = await adapter.create_user(
        CreateUserSchema(email="haspw@test.com", password="securepass123"),
        hashed_password="hashed",
    )
    passkey = await adapter.store_passkey(_passkey(user.id))

    async with _client(app) as client:
        r = await client.delete(
            f"/api/v1/auth/passkeys/{passkey.id}", headers=_headers(fullauth, user)
        )
        assert r.status_code == 204
        assert await adapter.get_user_passkeys(user.id) == []


@pytest.mark.asyncio
async def test_unlinking_a_provider_the_user_does_not_have_is_404(passkey_config, adapter):
    app, fullauth = _app(passkey_config, adapter, providers=[_Provider()])
    user = await _passwordless_user(adapter)
    await adapter.create_oauth_account(_oauth(user.id))

    async with _client(app) as client:
        r = await client.delete(
            "/api/v1/auth/oauth/accounts/github", headers=_headers(fullauth, user)
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_a_passkey_does_not_count_when_passkey_sign_in_is_off(config, adapter):
    """Turning PASSKEY_ENABLED off leaves the rows behind but removes the way to
    sign in with them. Counting one would allow the lockout this rule prevents."""
    app, fullauth = _app(config, adapter, providers=[_Provider()])  # passkeys disabled
    user = await _passwordless_user(adapter)
    await adapter.create_oauth_account(_oauth(user.id))
    await adapter.store_passkey(_passkey(user.id))

    async with _client(app) as client:
        r = await client.delete(
            "/api/v1/auth/oauth/accounts/google", headers=_headers(fullauth, user)
        )
        assert r.status_code == 400
        # And the advice does not mention passkeys, since they are not available.
        assert "passkey" not in r.json()["detail"]
        assert len(await adapter.get_user_oauth_accounts(user.id)) == 1


@pytest.mark.asyncio
async def test_a_link_to_an_unconfigured_provider_does_not_count(passkey_config, adapter):
    """A provider dropped from the configured list cannot be signed in with, so
    an old row for it is not a way back into the account."""
    # google is configured; the user's only link is to a provider that is not.
    app, fullauth = _app(passkey_config, adapter, providers=[_Provider()])
    user = await _passwordless_user(adapter)
    await adapter.create_oauth_account(_oauth(user.id, provider="retired-provider"))
    passkey = await adapter.store_passkey(_passkey(user.id))

    async with _client(app) as client:
        r = await client.delete(
            f"/api/v1/auth/passkeys/{passkey.id}", headers=_headers(fullauth, user)
        )
        assert r.status_code == 400
        assert len(await adapter.get_user_passkeys(user.id)) == 1


# ── Proving presence ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deleting_an_account_needs_recent_authentication(config, adapter):
    app, fullauth = _app(config, adapter)
    user = await adapter.create_user(
        CreateUserSchema(email="doomed@test.com", password="securepass123"),
        hashed_password="$argon2id$v=19$m=65536,t=3,p=4$placeholder",
    )

    async with _client(app) as client:
        stale = _headers(fullauth, user, auth_age_seconds=3600)
        r = await client.request("DELETE", "/api/v1/auth/me", headers=stale)
        assert r.status_code == 403
        assert r.json()["detail"] == "Re-authentication required"
        assert await adapter.get_user_by_id(user.id) is not None

        fresh = _headers(fullauth, user, auth_age_seconds=10)
        r = await client.request("DELETE", "/api/v1/auth/me", headers=fresh)
        assert r.status_code == 204
        assert await adapter.get_user_by_id(user.id) is None


@pytest.mark.asyncio
async def test_the_current_password_also_proves_presence(config, adapter, client, auth_headers):
    """A stale session can still delete by supplying the password."""
    fullauth = client._transport.app.state.fullauth
    user = await fullauth.adapter.get_user_by_email("user@test.com")
    stale = _headers(fullauth, user, auth_age_seconds=3600)

    r = await client.request(
        "DELETE", "/api/v1/auth/me", headers=stale, json={"current_password": "wrong-password"}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "Current password is incorrect"

    r = await client.request(
        "DELETE", "/api/v1/auth/me", headers=stale, json={"current_password": "securepass123"}
    )
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_setting_a_first_password_needs_recent_authentication(config, adapter):
    """There is no current password to check, and it creates a new way in."""
    app, fullauth = _app(config, adapter)
    user = await _passwordless_user(adapter)
    body = {"new_password": "brand-new-pass-123"}

    async with _client(app) as client:
        r = await client.post(
            "/api/v1/auth/change-password",
            json=body,
            headers=_headers(fullauth, user, auth_age_seconds=3600),
        )
        assert r.status_code == 403
        assert await adapter.get_hashed_password(user.id) is None

        r = await client.post(
            "/api/v1/auth/change-password",
            json=body,
            headers=_headers(fullauth, user, auth_age_seconds=10),
        )
        assert r.status_code == 200
        assert await adapter.get_hashed_password(user.id) is not None


@pytest.mark.asyncio
async def test_refreshing_does_not_renew_the_authentication_time(client, login_tokens, app):
    """Otherwise anyone holding a refresh token could mint their way past the
    re-authentication check."""
    fullauth = app.state.fullauth
    original = (
        await fullauth.token_engine.decode_token(
            login_tokens["access_token"], expected_type="access"
        )
    ).auth_time
    assert original is not None

    r = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": login_tokens["refresh_token"]}
    )
    assert r.status_code == 200
    rotated = await fullauth.token_engine.decode_token(
        r.json()["access_token"], expected_type="access"
    )
    assert rotated.auth_time == original


# ── Token and password hygiene ───────────────────────────────────────


@pytest.mark.asyncio
async def test_a_password_reset_link_dies_when_the_password_changes(config, adapter):
    """Two links in an inbox, or a link plus a deliberate change: only the
    newest may work."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import TokenError
    from fastapi_fullauth.flows.password_reset import request_password_reset, reset_password

    engine = TokenEngine(config=config)
    user = await adapter.create_user(
        CreateUserSchema(email="reset@test.com", password="securepass123"),
        hashed_password="hashed-original",
    )

    first = await request_password_reset(adapter, engine, "reset@test.com")
    second = await request_password_reset(adapter, engine, "reset@test.com")
    assert first and second

    await reset_password(adapter, engine, second, "new-securepass-123")

    with pytest.raises(TokenError):
        await reset_password(adapter, engine, first, "attacker-chosen-pass")
    assert user is not None


@pytest.mark.asyncio
async def test_no_verification_token_for_an_already_verified_account(config, adapter):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.email_verify import create_email_verification_token

    engine = TokenEngine(config=config)
    user = await adapter.create_user(
        CreateUserSchema(email="verified@test.com", password="securepass123"),
        hashed_password="x",
    )
    assert await create_email_verification_token(adapter, engine, user.id) is not None

    await adapter.set_user_verified(user.id)
    assert await create_email_verification_token(adapter, engine, user.id) is None


@pytest.mark.asyncio
async def test_registering_rejects_an_oversized_password(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "huge@test.com", "password": "a" * 5000},
    )
    assert r.status_code == 422
    assert "at most" in r.json()["detail"]


@pytest.mark.asyncio
async def test_pruning_removes_expired_refresh_tokens_only(adapter):
    """Rotation writes a row per refresh, so the table has to be prunable. A
    revoked but unexpired row must survive: it is what a replayed token is
    matched against."""
    from fastapi_fullauth.types import RefreshToken as RefreshTokenSchema

    user = await adapter.create_user(
        CreateUserSchema(email="prune@test.com", password="securepass123"),
        hashed_password="x",
    )
    now = datetime.now(timezone.utc)

    async def store(token: str, expires_at: datetime, revoked: bool = False) -> None:
        await adapter.store_refresh_token(
            RefreshTokenSchema(
                token=token,
                user_id=user.id,
                expires_at=expires_at,
                family_id="fam",
                revoked=revoked,
            )
        )

    await store("live", now + timedelta(days=1))
    await store("revoked-but-live", now + timedelta(days=1), revoked=True)
    await store("expired", now - timedelta(days=1))
    await store("expired-revoked", now - timedelta(days=1), revoked=True)

    assert await adapter.prune_expired_refresh_tokens() == 2

    assert await adapter.get_refresh_token("live") is not None
    assert await adapter.get_refresh_token("revoked-but-live") is not None
    assert await adapter.get_refresh_token("expired") is None
    assert await adapter.get_refresh_token("expired-revoked") is None


@pytest.mark.asyncio
async def test_rotating_a_token_from_before_auth_time_does_not_refresh_it(config, adapter):
    """Upgrade path: tokens minted before the claim existed carry no auth_time.
    Rotating one must not stamp it with "now", or every such token in the wild
    would become a re-authentication bypass for its whole 30-day life."""
    import jwt

    from fastapi_fullauth.core.crypto import hash_refresh_token
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.refresh import refresh
    from fastapi_fullauth.types import RefreshToken as RefreshTokenSchema

    engine = TokenEngine(config=config)
    user = await adapter.create_user(
        CreateUserSchema(email="legacy@test.com", password="securepass123"),
        hashed_password="x",
    )

    # Exactly what the previous release issued: no auth_time, and signed in days
    # ago, which is the case that matters.
    signed_in_at = datetime.now(timezone.utc) - timedelta(days=3)
    legacy = jwt.encode(
        {
            "sub": str(user.id),
            "exp": datetime.now(timezone.utc) + timedelta(days=27),
            "iat": signed_in_at,
            "jti": uuid4().hex,
            "type": "refresh",
            "family_id": "legacy-family",
        },
        config.SECRET_KEY,
        algorithm=config.ALGORITHM,
    )
    await adapter.store_refresh_token(
        RefreshTokenSchema(
            token=hash_refresh_token(legacy),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=27),
            family_id="legacy-family",
        )
    )

    pair = await refresh(adapter, engine, legacy)
    rotated = await engine.decode_token(pair.access_token, expected_type="access")

    assert rotated.auth_time is not None
    # Three days old, not seconds: rotation carried the original time through.
    age = (datetime.now(timezone.utc) - rotated.auth_time).total_seconds()
    assert age > 60 * 60 * 24 * 2

    # And the session is therefore still too stale for a destructive action.
    from fastapi_fullauth.exceptions import AuthenticationError
    from fastapi_fullauth.flows.reauth import verify_recent_auth

    with pytest.raises(AuthenticationError):
        await verify_recent_auth(rotated, hashed_password=None, max_age_seconds=300)


@pytest.mark.asyncio
async def test_the_password_check_on_delete_is_rate_limited(config, adapter):
    """Whoever holds the token can guess the password here, and a correct guess
    deletes the account, so the attempts are metered like a sign-in."""
    app, fullauth = _app(config, adapter)
    user = await adapter.create_user(
        CreateUserSchema(email="oracle@test.com", password="securepass123"),
        hashed_password="$argon2id$v=19$m=65536,t=3,p=4$placeholder",
    )
    stale = _headers(fullauth, user, auth_age_seconds=3600)

    statuses = []
    async with _client(app) as client:
        for _ in range(fullauth.config.AUTH_RATE_LIMITS.reauth + 2):
            r = await client.request(
                "DELETE",
                "/api/v1/auth/me",
                headers=stale,
                json={"current_password": "wrong-guess"},
            )
            statuses.append(r.status_code)

    assert 429 in statuses, statuses
    assert await adapter.get_user_by_id(user.id) is not None


@pytest.mark.asyncio
async def test_login_rejects_an_oversized_password_without_hashing_it(config, adapter):
    """The cap exists to stop a body being turned into hashing work, and login is
    the path an attacker can reach without an account."""
    import importlib
    from unittest.mock import AsyncMock

    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import AuthenticationError

    # Patched by object, not by name: on 3.10 "flows.login" resolves to the
    # re-exported function rather than the module.
    login_module = importlib.import_module("fastapi_fullauth.flows.login")
    await adapter.create_user(
        CreateUserSchema(email="long@test.com", password="securepass123"),
        hashed_password="x",
    )

    verify = AsyncMock(return_value=True)
    with (
        patch.object(login_module, "averify_password", verify),
        pytest.raises(AuthenticationError),
    ):
        await login_module.login(
            adapter=adapter,
            token_engine=TokenEngine(config=config),
            identifier="long@test.com",
            password="a" * 5000,
            prevent_timing_attacks=True,
            max_password_length=config.PASSWORD_MAX_LENGTH,
        )

    verify.assert_not_awaited()
