"""Tests for OAuth2 social login."""

from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.exceptions import OAuthAccountAlreadyLinkedError
from fastapi_fullauth.flows.oauth import (
    build_link_authorization_url,
    generate_oauth_state,
    link_oauth_account,
    oauth_callback,
    verify_oauth_state,
)
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import CreateUserSchema, OAuthUserInfo
from fastapi_fullauth.types import OAuthAccount as OAuthAccountSchema
from tests.conftest import OAuthAccount, RefreshToken, Role, User, UserRole

BINDING = "client-binding-secret"

# ── Mock provider ────────────────────────────────────────────────────


class MockOAuthProvider(OAuthProvider):
    name = "mock"

    def __init__(self, user_info: OAuthUserInfo | None = None):
        self.client_id = "test-id"
        self.client_secret = "test-secret"
        self.redirect_uris = ["http://localhost/callback"]
        self.scopes = self.default_scopes
        self._user_info = user_info or OAuthUserInfo(
            provider="mock",
            provider_user_id="mock-user-123",
            email="oauth@example.com",
            email_verified=True,
            name="Test User",
        )

    @property
    def default_scopes(self) -> list[str]:
        return ["email", "profile"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        return f"https://mock.provider/auth?state={state}&redirect_uri={redirect_uri}"

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        return {"access_token": "mock-access-token", "refresh_token": "mock-refresh-token"}

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        return self._user_info


class PkceMockProvider(OAuthProvider):
    name = "pkce-mock"
    supports_pkce = True

    def __init__(self) -> None:
        self.client_id = "test-id"
        self.client_secret = "test-secret"
        self.redirect_uris = ["http://localhost/callback"]
        self.scopes = self.default_scopes
        self.seen_state: str | None = None
        self.seen_challenge: str | None = None
        self.seen_verifier: str | None = None

    @property
    def default_scopes(self) -> list[str]:
        return ["email"]

    def get_authorization_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        self.seen_state = state
        self.seen_challenge = code_challenge
        return f"https://pkce.provider/auth?state={state}&code_challenge={code_challenge}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict:
        self.seen_verifier = code_verifier
        return {"access_token": "mock-access-token", "refresh_token": "mock-refresh-token"}

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="pkce-mock",
            provider_user_id="pkce-user-1",
            email="pkce@example.com",
            email_verified=True,
            name="PKCE User",
        )


# ── Fixtures ─────────────────────────────────────────────────────────


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


@pytest.fixture
def config():
    return FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        JWT_LEEWAY_SECONDS=0,
    )


@pytest.fixture
async def adapter():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        role_model=Role,
        user_role_model=UserRole,
        oauth_account_model=OAuthAccount,
    )
    yield adapter
    await engine.dispose()


@pytest.fixture
def fullauth_with_oauth(config, adapter):
    return FullAuth(config=config, adapter=adapter, providers=[MockOAuthProvider()])


@pytest.fixture
def oauth_app(fullauth_with_oauth):
    app = FastAPI()
    fullauth_with_oauth.init_app(app)
    return app


# ── State token tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_and_verify_oauth_state(config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    state = generate_oauth_state(engine, ttl_seconds=300, binding=BINDING)
    await verify_oauth_state(engine, state, binding=BINDING)


@pytest.mark.asyncio
async def test_verify_invalid_state_raises(config):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import OAuthProviderError

    engine = TokenEngine(config=config)
    # create a regular access token (no purpose)
    token = engine.create_access_token(user_id="test")
    with pytest.raises(OAuthProviderError, match="Invalid OAuth state"):
        await verify_oauth_state(engine, token, binding=BINDING)


@pytest.mark.asyncio
async def test_oauth_state_ttl_is_applied(config):
    """State token should expire based on ttl_seconds, not ACCESS_TOKEN_EXPIRE_MINUTES."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import TokenExpiredError

    engine = TokenEngine(config=config)
    # create state with 1-second TTL
    state = generate_oauth_state(engine, ttl_seconds=1, binding=BINDING)

    import asyncio

    await asyncio.sleep(1.1)

    with pytest.raises(TokenExpiredError):
        await verify_oauth_state(engine, state, binding=BINDING)


# ── OAuth callback flow tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth_creates_new_user(adapter, config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()
    state = generate_oauth_state(engine, binding=BINDING)

    token_pair, user, is_new, info = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
        binding=BINDING,
    )

    assert is_new is True
    assert user.email == "oauth@example.com"
    assert user.is_verified is True
    assert token_pair.access_token
    assert token_pair.refresh_token


@pytest.mark.asyncio
async def test_oauth_links_existing_user(adapter, config):
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.types import CreateUserSchema

    engine = TokenEngine(config=config)

    # create existing user with same email
    data = CreateUserSchema(email="oauth@example.com", password="existing-pass")
    existing = await adapter.create_user(data, hashed_password=hash_password("existing-pass"))

    provider = MockOAuthProvider()
    state = generate_oauth_state(engine, binding=BINDING)

    token_pair, user, is_new, info = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
        binding=BINDING,
    )

    assert is_new is False
    assert user.id == existing.id

    # check OAuth account was linked
    account = await adapter.get_oauth_account("mock", "mock-user-123")
    assert account is not None
    assert account.user_id == existing.id


@pytest.mark.asyncio
async def test_oauth_state_is_single_use(adapter, config):
    """A state token must not be replayable: a second callback with the same
    state is rejected even though the first succeeded."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import TokenError

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()
    state = generate_oauth_state(engine, binding=BINDING)

    # first use succeeds
    await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
        binding=BINDING,
    )

    # replaying the same state is rejected (it was burned on first use)
    with pytest.raises(TokenError):
        await oauth_callback(
            adapter=adapter,
            token_engine=engine,
            provider=provider,
            code="test-code",
            state=state,
            binding=BINDING,
        )


@pytest.mark.asyncio
async def test_wrong_binding_is_rejected_without_burning_the_state(adapter, config):
    """A mismatched binding must fail before the state is consumed, so a forged
    attempt cannot use up the legitimate client's state."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import OAuthProviderError

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()
    state = generate_oauth_state(engine, binding=BINDING)

    with pytest.raises(OAuthProviderError, match="Invalid OAuth state"):
        await oauth_callback(
            adapter=adapter,
            token_engine=engine,
            provider=provider,
            code="test-code",
            state=state,
            binding="someone-elses-binding",
        )

    _, user, _, _ = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
        binding=BINDING,
    )
    assert user.email == "oauth@example.com"


@pytest.mark.asyncio
async def test_state_carries_only_a_digest_of_the_binding(config):
    """The state travels through the browser and the provider; the secret itself
    must never be readable from it."""
    import jwt

    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    state = generate_oauth_state(engine, binding=BINDING)
    claims = jwt.decode(state, options={"verify_signature": False})
    assert BINDING not in state
    assert BINDING not in str(claims)
    assert claims["extra"]["binding"]


@pytest.mark.asyncio
async def test_oauth_unverified_email_refuses_link_to_existing_account(adapter, config):
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.types import CreateUserSchema, OAuthUserInfo

    engine = TokenEngine(config=config)

    data = CreateUserSchema(email="victim@example.com", password="existing-pass")
    await adapter.create_user(data, hashed_password=hash_password("existing-pass"))

    provider = MockOAuthProvider(
        user_info=OAuthUserInfo(
            provider="mock",
            provider_user_id="attacker-42",
            email="victim@example.com",
            email_verified=False,
            name="Attacker",
        )
    )
    state = generate_oauth_state(engine, binding=BINDING)

    with pytest.raises(OAuthProviderError):
        await oauth_callback(
            adapter=adapter,
            token_engine=engine,
            provider=provider,
            code="c",
            state=state,
            binding=BINDING,
        )

    # no OAuth account created, existing user not hijacked
    assert await adapter.get_oauth_account("mock", "attacker-42") is None


@pytest.mark.asyncio
async def test_oauth_returning_user(adapter, config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()

    # first login = creates user
    state1 = generate_oauth_state(engine, binding=BINDING)
    _, user1, is_new1, _ = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="code1",
        state=state1,
        binding=BINDING,
    )
    assert is_new1 is True

    # second login = returning user
    state2 = generate_oauth_state(engine, binding=BINDING)
    _, user2, is_new2, _ = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="code2",
        state=state2,
        binding=BINDING,
    )
    assert is_new2 is False
    assert user1.id == user2.id


# ── Route tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_providers(oauth_app):
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/auth/oauth/providers")
        assert r.status_code == 200
        assert "mock" in r.json()["providers"]


@pytest.mark.asyncio
async def test_authorize_url(oauth_app):
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(
            "/api/v1/auth/oauth/mock/authorize",
            params={"redirect_uri": "http://localhost/callback"},
        )
        assert r.status_code == 200
        assert "https://mock.provider/auth" in r.json()["authorization_url"]


@pytest.mark.asyncio
async def test_authorize_unknown_provider(oauth_app):
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(
            "/api/v1/auth/oauth/unknown/authorize",
            params={"redirect_uri": "http://localhost/callback"},
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_callback_creates_user_and_returns_tokens(oauth_app, fullauth_with_oauth):
    transport = ASGITransport(app=oauth_app)
    state = generate_oauth_state(fullauth_with_oauth.token_engine, binding=BINDING)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "test-code", "state": state, "binding": BINDING},
        )
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data


@pytest.mark.asyncio
async def test_callback_rejects_a_state_issued_to_another_client(oauth_app):
    """Login CSRF: an attacker starts a login, then makes the victim's browser
    submit the attacker's code and state, signing the victim into the
    attacker's account. The state must be bound to the client that requested
    it, so the victim's own binding cannot redeem the attacker's state."""
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        params = {"redirect_uri": "http://localhost/callback"}
        attacker = (await client.get("/api/v1/auth/oauth/mock/authorize", params=params)).json()
        victim = (await client.get("/api/v1/auth/oauth/mock/authorize", params=params)).json()
        attacker_state = parse_qs(urlparse(attacker["authorization_url"]).query)["state"][0]

        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "attacker-code", "state": attacker_state, "binding": victim["binding"]},
        )
        assert r.status_code == 400

        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "attacker-code", "state": attacker_state},
        )
        assert r.status_code == 422

        # The client that started the flow can still finish it.
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "code", "state": attacker_state, "binding": attacker["binding"]},
        )
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_callback_invalid_state(oauth_app):
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "test-code", "state": "bad-state", "binding": BINDING},
        )
        assert r.status_code == 400


# ── PKCE tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pkce_challenge_matches_verifier_end_to_end(adapter, config):
    """authorize sends an S256 challenge; callback derives the matching verifier."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import (
        _pkce_code_challenge,
        build_authorization_url,
        oauth_callback,
    )

    engine = TokenEngine(config=config)
    provider = PkceMockProvider()

    url = build_authorization_url(
        engine, provider, "http://localhost/callback", pkce_enabled=True, binding=BINDING
    )
    assert "code_challenge=" in url
    assert provider.seen_challenge is not None
    assert provider.seen_state is not None

    await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=provider.seen_state,
        binding=BINDING,
        pkce_enabled=True,
    )

    assert provider.seen_verifier is not None
    # The verifier the provider received at token exchange must hash to the
    # challenge it was given at authorize time.
    assert _pkce_code_challenge(provider.seen_verifier) == provider.seen_challenge


@pytest.mark.asyncio
async def test_pkce_disabled_sends_no_challenge_or_verifier(adapter):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import build_authorization_url, oauth_callback

    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        JWT_LEEWAY_SECONDS=0,
        OAUTH_PKCE_ENABLED=False,
    )
    engine = TokenEngine(config=config)
    provider = PkceMockProvider()

    build_authorization_url(
        engine, provider, "http://localhost/callback", pkce_enabled=False, binding=BINDING
    )
    assert provider.seen_challenge is None

    await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=provider.seen_state,
        binding=BINDING,
        pkce_enabled=False,
    )
    assert provider.seen_verifier is None


@pytest.mark.asyncio
async def test_pkce_skipped_for_provider_without_support(adapter, config):
    """Providers that don't opt in keep their old two-argument signatures."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import build_authorization_url

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()  # supports_pkce is False
    url = build_authorization_url(
        engine, provider, "http://localhost/callback", pkce_enabled=True, binding=BINDING
    )
    assert "code_challenge" not in url


@pytest.mark.asyncio
async def test_google_authorization_url_includes_pkce(config):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import build_authorization_url
    from fastapi_fullauth.oauth.google import GoogleOAuthProvider

    engine = TokenEngine(config=config)
    provider = GoogleOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    url = build_authorization_url(engine, provider, "http://localhost/cb", binding=BINDING)
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    await provider.aclose()


# ── Adapter tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sqlmodel_adapter_oauth_crud(adapter):
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema, OAuthAccount

    # OAuth accounts need a valid user_id (foreign key constraint)
    data = CreateUserSchema(email="oauthuser@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    account = OAuthAccount(
        provider="google",
        provider_user_id="g-123",
        user_id=user.id,
        provider_email="test@gmail.com",
    )

    created = await adapter.create_oauth_account(account)
    assert created.provider == "google"

    fetched = await adapter.get_oauth_account("google", "g-123")
    assert fetched is not None
    assert fetched.user_id == user.id

    updated = await adapter.update_oauth_account("google", "g-123", {"access_token": "new-token"})
    assert updated.access_token == "new-token"

    accounts = await adapter.get_user_oauth_accounts(user.id)
    assert len(accounts) == 1

    await adapter.delete_oauth_account("google", "g-123")
    assert await adapter.get_oauth_account("google", "g-123") is None


# ── Resource lifecycle ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth_provider_pools_and_closes_http_client():
    from fastapi_fullauth.oauth.google import GoogleOAuthProvider

    provider = GoogleOAuthProvider(
        client_id="id",
        client_secret="secret",
        redirect_uris=["http://localhost/cb"],
    )

    client = provider._client()
    assert provider._client() is client  # reused across calls
    assert client.is_closed is False

    await provider.aclose()
    assert client.is_closed is True
    assert provider._http_client is None

    await provider.aclose()  # idempotent

    fresh = provider._client()
    assert fresh is not client
    await provider.aclose()


@pytest.mark.asyncio
async def test_fullauth_aclose_closes_providers_and_is_idempotent(adapter, config):
    from fastapi_fullauth.oauth.google import GoogleOAuthProvider

    provider = GoogleOAuthProvider(
        client_id="id",
        client_secret="secret",
        redirect_uris=["http://localhost/cb"],
    )
    fullauth = FullAuth(config=config, adapter=adapter, providers=[provider])
    client = provider._client()

    await fullauth.aclose()
    assert client.is_closed is True
    assert provider._http_client is None

    await fullauth.aclose()  # idempotent, also fine with memory backends


@pytest.mark.asyncio
async def test_fullauth_aclose_tolerates_provider_without_init(adapter, config):
    # MockOAuthProvider skips super().__init__(); aclose must still be a no-op.
    fullauth = FullAuth(config=config, adapter=adapter, providers=[MockOAuthProvider()])
    await fullauth.aclose()


@pytest.mark.asyncio
async def test_oauth_login_blocked_for_deactivated_user(adapter, config):
    """A deactivated account must not be able to sign in through a linked OAuth
    account - parity with the password and passkey flows."""
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.types import CreateUserSchema

    engine = TokenEngine(config=config)

    # existing account on the same email, then deactivated by an admin
    data = CreateUserSchema(email="oauth@example.com", password="existing-pass")
    existing = await adapter.create_user(data, hashed_password=hash_password("existing-pass"))
    await adapter.update_user(existing.id, {"is_active": False})

    provider = MockOAuthProvider()
    state = generate_oauth_state(engine, binding=BINDING)

    with pytest.raises(OAuthProviderError, match="deactivated"):
        await oauth_callback(
            adapter=adapter,
            token_engine=engine,
            provider=provider,
            code="test-code",
            state=state,
            binding=BINDING,
        )

    # Refused before any write: the provider identity is not linked to the account.
    assert await adapter.get_oauth_account("mock", "mock-user-123") is None


@pytest.mark.asyncio
async def test_google_userinfo_rejects_token_response_without_access_token():
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.oauth.google import GoogleOAuthProvider

    provider = GoogleOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    with pytest.raises(OAuthProviderError, match="token exchange failed"):
        await provider.get_user_info({})  # no access_token, must not KeyError


@pytest.mark.asyncio
async def test_github_userinfo_rejects_token_response_without_access_token():
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.oauth.github import GitHubOAuthProvider

    provider = GitHubOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    with pytest.raises(OAuthProviderError, match="token exchange failed"):
        await provider.get_user_info({})  # no access_token, must not KeyError


# ── Discord provider ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discord_authorization_url_includes_pkce_and_scopes(config):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import build_authorization_url
    from fastapi_fullauth.oauth.discord import DiscordOAuthProvider

    engine = TokenEngine(config=config)
    provider = DiscordOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    url = build_authorization_url(engine, provider, "http://localhost/cb", binding=BINDING)
    assert url.startswith("https://discord.com/oauth2/authorize?")
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "scope=identify+email" in url
    await provider.aclose()


@pytest.mark.asyncio
async def test_discord_userinfo_rejects_token_response_without_access_token():
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.oauth.discord import DiscordOAuthProvider

    provider = DiscordOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    with pytest.raises(OAuthProviderError, match="token exchange failed"):
        await provider.get_user_info({})  # no access_token, must not KeyError
    await provider.aclose()


@pytest.mark.asyncio
async def test_discord_userinfo_maps_fields():
    import httpx

    from fastapi_fullauth.oauth.discord import DiscordOAuthProvider

    payload = {
        "id": "80351110224678912",
        "username": "nelly",
        "global_name": "Nelly",
        "avatar": "8342729096ea3675442027381ff50dfe",
        "email": "nelly@discord.com",
        "verified": True,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://discord.com/api/users/@me"
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json=payload)

    provider = DiscordOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    provider._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    info = await provider.get_user_info({"access_token": "tok"})
    assert info.provider == "discord"
    assert info.provider_user_id == "80351110224678912"
    assert info.email == "nelly@discord.com"
    assert info.email_verified is True
    assert info.name == "Nelly"
    assert info.picture == (
        "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png"
    )
    await provider.aclose()


@pytest.mark.asyncio
async def test_discord_userinfo_falls_back_to_username_and_null_avatar():
    import httpx

    from fastapi_fullauth.oauth.discord import DiscordOAuthProvider

    # No global_name and no avatar: name falls back to username, picture is None.
    payload = {"id": "42", "username": "legacy_user", "avatar": None, "email": "x@y.z"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    provider = DiscordOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    provider._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    info = await provider.get_user_info({"access_token": "tok"})
    assert info.name == "legacy_user"
    assert info.picture is None
    assert info.email_verified is False  # `verified` absent -> False
    await provider.aclose()


# ── GitLab provider ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gitlab_authorization_url_includes_pkce_and_scopes(config):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.flows.oauth import build_authorization_url
    from fastapi_fullauth.oauth.gitlab import GitLabOAuthProvider

    engine = TokenEngine(config=config)
    provider = GitLabOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    url = build_authorization_url(engine, provider, "http://localhost/cb", binding=BINDING)
    assert url.startswith("https://gitlab.com/oauth/authorize?")
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "scope=openid+email+profile" in url
    await provider.aclose()


@pytest.mark.asyncio
async def test_gitlab_userinfo_rejects_token_response_without_access_token():
    from fastapi_fullauth.exceptions import OAuthProviderError
    from fastapi_fullauth.oauth.gitlab import GitLabOAuthProvider

    provider = GitLabOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    with pytest.raises(OAuthProviderError, match="token exchange failed"):
        await provider.get_user_info({})  # no access_token, must not KeyError
    await provider.aclose()


@pytest.mark.asyncio
async def test_gitlab_userinfo_maps_fields():
    import httpx

    from fastapi_fullauth.oauth.gitlab import GitLabOAuthProvider

    # GitLab OIDC userinfo (sub can arrive as an int; it must be stringified).
    payload = {
        "sub": 12345,
        "name": "Ada Lovelace",
        "email": "ada@gitlab.com",
        "email_verified": True,
        "picture": "https://gitlab.com/uploads/avatar.png",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://gitlab.com/oauth/userinfo"
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json=payload)

    provider = GitLabOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    provider._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    info = await provider.get_user_info({"access_token": "tok"})
    assert info.provider == "gitlab"
    assert info.provider_user_id == "12345"  # stringified
    assert info.email == "ada@gitlab.com"
    assert info.email_verified is True
    assert info.name == "Ada Lovelace"
    assert info.picture == "https://gitlab.com/uploads/avatar.png"
    await provider.aclose()


# ── Provider failures surface as OAuthProviderError, never a 500 ─────


def _google_with_transport(handler):
    import httpx

    from fastapi_fullauth.oauth.google import GoogleOAuthProvider

    provider = GoogleOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    provider._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return provider


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["timeout", "connection", "html_body", "json_list"],
)
async def test_token_exchange_failures_raise_oauth_provider_error(failure):
    import httpx

    from fastapi_fullauth.exceptions import OAuthProviderError

    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ConnectTimeout("timed out", request=request)
        if failure == "connection":
            raise httpx.ConnectError("refused", request=request)
        if failure == "html_body":
            return httpx.Response(200, text="<html>maintenance</html>")
        return httpx.Response(200, json=["unexpected"])

    provider = _google_with_transport(handler)
    with pytest.raises(OAuthProviderError, match="token exchange failed"):
        await provider.exchange_code("code", "http://localhost/cb")
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "html_body", "json_list"])
async def test_userinfo_failures_raise_oauth_provider_error(failure):
    import httpx

    from fastapi_fullauth.exceptions import OAuthProviderError

    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        if failure == "html_body":
            return httpx.Response(200, text="not json")
        return httpx.Response(200, json=["unexpected"])

    provider = _google_with_transport(handler)
    with pytest.raises(OAuthProviderError, match="Failed to fetch user info"):
        await provider.get_user_info({"access_token": "tok"})
    await provider.aclose()


@pytest.mark.asyncio
async def test_github_emails_endpoint_failure_falls_back_to_unverified_profile_email():
    """The emails call is best-effort, as a non-200 already was: a network error
    there must not fail the login, and the email stays unverified."""
    import httpx

    from fastapi_fullauth.oauth.github import GitHubOAuthProvider

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user/emails":
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={"id": 7, "email": "gh@example.com", "name": "GH"})

    provider = GitHubOAuthProvider(
        client_id="id", client_secret="secret", redirect_uris=["http://localhost/cb"]
    )
    provider._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    info = await provider.get_user_info({"access_token": "tok"})
    assert info.provider_user_id == "7"
    assert info.email == "gh@example.com"
    assert info.email_verified is False
    await provider.aclose()


@pytest.mark.asyncio
async def test_callback_returns_400_when_the_provider_is_unreachable(adapter, config):
    import httpx

    from fastapi_fullauth.flows.oauth import generate_oauth_binding

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    provider = _google_with_transport(handler)
    fullauth = FullAuth(config=config, adapter=adapter, providers=[provider])
    app = FastAPI()
    fullauth.init_app(app)

    binding = generate_oauth_binding()
    state = generate_oauth_state(fullauth.token_engine, binding=binding)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/oauth/google/callback",
            json={"code": "c", "state": state, "binding": binding},
        )
    assert r.status_code == 400
    await provider.aclose()


# ── Linking a provider while signed in ───────────────────────────

REDIRECT = "http://localhost/callback"


def _identity(provider_user_id: str, email: str = "linked@example.com") -> OAuthUserInfo:
    return OAuthUserInfo(
        provider="mock",
        provider_user_id=provider_user_id,
        email=email,
        email_verified=True,
        name="Linked User",
    )


def _app_with(config, adapter, provider):
    fullauth = FullAuth(config=config, adapter=adapter, providers=[provider])
    app = FastAPI()
    fullauth.init_app(app)
    return app, fullauth


def _state_of(authorization_url: str) -> str:
    return parse_qs(urlparse(authorization_url).query)["state"][0]


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _sign_in(client, email: str = "owner@example.com") -> dict:
    body = {"email": email, "password": "securepass123"}
    await client.post("/api/v1/auth/register", json=body)
    login = await client.post("/api/v1/auth/login", json=body)
    return {"Authorization": "Bearer " + login.json()["access_token"]}


async def _start_link(client, headers, provider: str = "mock"):
    r = await client.get(
        "/api/v1/auth/oauth/" + provider + "/link/authorize",
        params={"redirect_uri": REDIRECT},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _link(client, headers, *, binding: str | None = None):
    """Run the whole link round trip and return the callback response."""
    started = await _start_link(client, headers)
    return await client.post(
        "/api/v1/auth/oauth/mock/link/callback",
        json={
            "code": "link-code",
            "state": _state_of(started["authorization_url"]),
            "binding": binding or started["binding"],
        },
        headers=headers,
    )


async def _linked_ids(client, headers) -> list:
    r = await client.get("/api/v1/auth/oauth/accounts", headers=headers)
    return [a["provider_user_id"] for a in r.json()]


@pytest.mark.asyncio
async def test_link_attaches_the_provider_without_touching_the_user(config, adapter):
    """Authorization comes from the session, so the provider email is stored for
    display only: it neither has to match the account nor verifies it."""
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1", "work@example.com")))
    async with _client(app) as client:
        headers = await _sign_in(client)

        r = await _link(client, headers)
        assert r.status_code == 200
        assert r.json() == {
            "provider": "mock",
            "provider_user_id": "gh-1",
            "provider_email": "work@example.com",
        }
        assert await _linked_ids(client, headers) == ["gh-1"]

        me = (await client.get("/api/v1/auth/me", headers=headers)).json()
        assert me["email"] == "owner@example.com"
        assert me["is_verified"] is False


@pytest.mark.asyncio
async def test_link_routes_require_authentication(oauth_app):
    async with _client(oauth_app) as client:
        r = await client.get(
            "/api/v1/auth/oauth/mock/link/authorize", params={"redirect_uri": REDIRECT}
        )
        assert r.status_code == 401

        r = await client.post(
            "/api/v1/auth/oauth/mock/link/callback",
            json={"code": "c", "state": "s", "binding": BINDING},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_link_is_idempotent(config, adapter):
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        headers = await _sign_in(client)

        assert (await _link(client, headers)).status_code == 200
        assert (await _link(client, headers)).status_code == 200
        assert await _linked_ids(client, headers) == ["gh-1"]


@pytest.mark.asyncio
async def test_link_refuses_an_identity_owned_by_another_user(config, adapter):
    """The takeover case: linking must never move an identity between accounts,
    or anyone could attach a victim's provider account and then sign in as them."""
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        owner = await _sign_in(client, "owner@example.com")
        assert (await _link(client, owner)).status_code == 200

        thief = await _sign_in(client, "thief@example.com")
        r = await _link(client, thief)
        assert r.status_code == 409
        assert "another user" in r.json()["detail"]

        assert await _linked_ids(client, thief) == []
        assert await _linked_ids(client, owner) == ["gh-1"]


@pytest.mark.asyncio
async def test_link_refuses_a_second_account_from_the_same_provider(config, adapter):
    """Unlinking resolves by provider alone, so two accounts for one provider
    would make it ambiguous."""
    provider = MockOAuthProvider(_identity("gh-1"))
    app, _ = _app_with(config, adapter, provider)
    async with _client(app) as client:
        headers = await _sign_in(client)
        assert (await _link(client, headers)).status_code == 200

        provider._user_info = _identity("gh-2", "second@example.com")
        r = await _link(client, headers)
        assert r.status_code == 409
        assert "already linked to a different" in r.json()["detail"]
        assert await _linked_ids(client, headers) == ["gh-1"]


@pytest.mark.asyncio
async def test_link_and_sign_in_states_are_not_interchangeable(config, adapter):
    app, fullauth = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        headers = await _sign_in(client)

        started = await _start_link(client, headers)
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={
                "code": "c",
                "state": _state_of(started["authorization_url"]),
                "binding": started["binding"],
            },
        )
        assert r.status_code == 400

        sign_in_state = generate_oauth_state(fullauth.token_engine, binding=BINDING)
        r = await client.post(
            "/api/v1/auth/oauth/mock/link/callback",
            json={"code": "c", "state": sign_in_state, "binding": BINDING},
            headers=headers,
        )
        assert r.status_code == 400
        assert await _linked_ids(client, headers) == []


@pytest.mark.asyncio
async def test_link_state_issued_for_another_user_is_rejected(config, adapter):
    """Even holding the matching binding, a state naming someone else must not
    attach that flow's identity to the caller."""
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        attacker = await _sign_in(client, "attacker@example.com")
        started = await _start_link(client, attacker)

        victim = await _sign_in(client, "victim@example.com")
        r = await client.post(
            "/api/v1/auth/oauth/mock/link/callback",
            json={
                "code": "c",
                "state": _state_of(started["authorization_url"]),
                "binding": started["binding"],
            },
            headers=victim,
        )
        assert r.status_code == 400
        assert await _linked_ids(client, victim) == []


@pytest.mark.asyncio
async def test_link_callback_rejects_a_wrong_binding(config, adapter):
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        headers = await _sign_in(client)
        r = await _link(client, headers, binding="not-the-binding")
        assert r.status_code == 400
        assert await _linked_ids(client, headers) == []


@pytest.mark.asyncio
async def test_link_state_is_useless_as_a_session_token(config, adapter):
    """The state rides in the address bar and reaches the provider, so it must
    not authenticate anything, even though it is an access-typed JWT."""
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        headers = await _sign_in(client)
        started = await _start_link(client, headers)
        state = _state_of(started["authorization_url"])

        r = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + state})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_link_authorize_validates_provider_and_redirect_uri(config, adapter):
    app, _ = _app_with(config, adapter, MockOAuthProvider(_identity("gh-1")))
    async with _client(app) as client:
        headers = await _sign_in(client)

        r = await client.get(
            "/api/v1/auth/oauth/unknown/link/authorize",
            params={"redirect_uri": REDIRECT},
            headers=headers,
        )
        assert r.status_code == 404

        r = await client.get(
            "/api/v1/auth/oauth/mock/link/authorize",
            params={"redirect_uri": "http://evil.test/callback"},
            headers=headers,
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_link_replaces_a_row_whose_owner_no_longer_exists(adapter):
    """Storage without cascading deletes can outlive the user; the orphan must
    not block the identity forever."""
    user = await adapter.create_user(
        CreateUserSchema(email="relink@example.com", password="securepass123"),
        hashed_password="x",
    )
    await adapter.create_oauth_account(
        OAuthAccountSchema(
            provider="mock",
            provider_user_id="gh-1",
            user_id=uuid4(),
            provider_email="ghost@example.com",
        )
    )

    account = await link_oauth_account(adapter, user, _identity("gh-1"), {"access_token": "t"})
    assert account.user_id == user.id
    assert [a.provider_user_id for a in await adapter.get_user_oauth_accounts(user.id)] == ["gh-1"]


@pytest.mark.asyncio
async def test_link_state_carries_the_user_id_outside_the_subject(config):
    """A real user id in `sub` would make the state a usable session token."""
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config)
    user_id = uuid4()
    url = build_link_authorization_url(
        engine, MockOAuthProvider(), REDIRECT, user_id, binding=BINDING
    )
    payload = await engine.decode_token(_state_of(url), expected_type="access")

    assert payload.sub == "oauth-state"
    assert payload.extra["link_user_id"] == str(user_id)
    assert payload.extra["purpose"] == "oauth_link"


@pytest.mark.asyncio
async def test_sign_in_refuses_a_second_identity_from_the_same_provider(config, adapter):
    """Two accounts at one provider can verify the same email. Attaching both to
    one user would leave `DELETE /oauth/accounts/{provider}` ambiguous: it
    resolves by provider alone, so it would delete one and leave the other."""
    provider = MockOAuthProvider(_identity("google-1", "dup@example.com"))
    app, fullauth = _app_with(config, adapter, provider)
    async with _client(app) as client:
        first = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={
                "code": "c",
                "state": generate_oauth_state(fullauth.token_engine, binding=BINDING),
                "binding": BINDING,
            },
        )
        assert first.status_code == 200
        headers = {"Authorization": "Bearer " + first.json()["access_token"]}

        provider._user_info = _identity("google-2", "dup@example.com")
        second = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={
                "code": "c",
                "state": generate_oauth_state(fullauth.token_engine, binding=BINDING),
                "binding": BINDING,
            },
        )
        # Generic, like every other sign-in failure: never a 500, and nothing
        # about the account is revealed to an unauthenticated caller.
        assert second.status_code == 400
        assert second.json()["detail"] == "OAuth authentication failed"
        assert await _linked_ids(client, headers) == ["google-1"]


@pytest.mark.asyncio
async def test_link_rejects_an_account_that_a_race_gave_to_someone_else(adapter):
    """Every adapter treats a duplicate insert as success and returns the row
    that won, so a lost race hands back another user's account. Reporting that
    as a successful link would tell the caller they own an identity they do not."""
    user = await adapter.create_user(
        CreateUserSchema(email="racer@example.com", password="securepass123"),
        hashed_password="x",
    )
    winner = await adapter.create_user(
        CreateUserSchema(email="winner@example.com", password="securepass123"),
        hashed_password="x",
    )
    foreign = OAuthAccountSchema(provider="mock", provider_user_id="gh-1", user_id=winner.id)

    with (
        patch.object(type(adapter), "create_oauth_account", AsyncMock(return_value=foreign)),
        pytest.raises(OAuthAccountAlreadyLinkedError),
    ):
        await link_oauth_account(adapter, user, _identity("gh-1"), {"access_token": "t"})


@pytest.mark.asyncio
async def test_oauth_routes_answer_501_on_an_adapter_without_oauth(config):
    """The combined router only mounts these when the adapter supports OAuth, but
    the routers are composable: mounted by hand, the adapter's RuntimeError would
    otherwise surface as a 500."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
    )
    fullauth = FullAuth(config=config, adapter=adapter, providers=[MockOAuthProvider()])
    app = FastAPI()
    fullauth.bind(app)
    app.include_router(fullauth.oauth_router)

    user = await adapter.create_user(
        CreateUserSchema(email="no-oauth@test.com", password="securepass123"),
        hashed_password="x",
    )
    token = fullauth.token_engine.create_access_token(user_id=str(user.id))
    headers = {"Authorization": "Bearer " + token}

    async with _client(app) as client:
        r = await client.get("/oauth/accounts", headers=headers)
        assert r.status_code == 501
        assert r.json()["detail"] == "Adapter does not support OAuth"

        r = await client.get(
            "/oauth/mock/link/authorize", params={"redirect_uri": REDIRECT}, headers=headers
        )
        assert r.status_code == 501

        r = await client.delete("/oauth/accounts/mock", headers=headers)
        assert r.status_code == 501

    await engine.dispose()
