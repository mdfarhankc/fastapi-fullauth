"""Tests for OAuth2 social login."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord  # noqa: F401
from fastapi_fullauth.flows.oauth import generate_oauth_state, oauth_callback, verify_oauth_state
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo
from tests.conftest import User

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


# ── Fixtures ─────────────────────────────────────────────────────────


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


@pytest.fixture
def config():
    return FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")


@pytest.fixture
async def adapter():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    yield adapter
    await engine.dispose()


@pytest.fixture
def fullauth_with_oauth(config, adapter):
    return FullAuth(config=config, adapter=adapter, providers=[MockOAuthProvider()])


@pytest.fixture
def oauth_app(fullauth_with_oauth):
    app = FastAPI()
    fullauth_with_oauth.init_app(app, auto_middleware=False)
    return app


# ── State token tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_and_verify_oauth_state(config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    state = generate_oauth_state(engine, ttl_seconds=300)
    await verify_oauth_state(engine, state)


@pytest.mark.asyncio
async def test_verify_invalid_state_raises(config):
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import OAuthProviderError

    engine = TokenEngine(config=config)
    # create a regular access token (no purpose)
    token = engine.create_access_token(user_id="test")
    with pytest.raises(OAuthProviderError, match="Invalid OAuth state"):
        await verify_oauth_state(engine, token)


@pytest.mark.asyncio
async def test_oauth_state_ttl_is_applied(config):
    """State token should expire based on ttl_seconds, not ACCESS_TOKEN_EXPIRE_MINUTES."""
    from fastapi_fullauth.core.tokens import TokenEngine
    from fastapi_fullauth.exceptions import TokenExpiredError

    engine = TokenEngine(config=config)
    # create state with 1-second TTL
    state = generate_oauth_state(engine, ttl_seconds=1)

    import asyncio

    await asyncio.sleep(1.1)

    with pytest.raises(TokenExpiredError):
        await verify_oauth_state(engine, state)


# ── OAuth callback flow tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth_creates_new_user(adapter, config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()
    state = generate_oauth_state(engine)

    token_pair, user, is_new, info = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
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
    state = generate_oauth_state(engine)

    token_pair, user, is_new, info = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="test-code",
        state=state,
    )

    assert is_new is False
    assert user.id == existing.id

    # check OAuth account was linked
    account = await adapter.get_oauth_account("mock", "mock-user-123")
    assert account is not None
    assert account.user_id == existing.id


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
    state = generate_oauth_state(engine)

    with pytest.raises(OAuthProviderError):
        await oauth_callback(
            adapter=adapter,
            token_engine=engine,
            provider=provider,
            code="c",
            state=state,
        )

    # no OAuth account created, existing user not hijacked
    assert await adapter.get_oauth_account("mock", "attacker-42") is None


@pytest.mark.asyncio
async def test_oauth_returning_user(adapter, config):
    from fastapi_fullauth.core.tokens import TokenEngine

    engine = TokenEngine(config=config)
    provider = MockOAuthProvider()

    # first login — creates user
    state1 = generate_oauth_state(engine)
    _, user1, is_new1, _ = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="code1",
        state=state1,
    )
    assert is_new1 is True

    # second login — returning user
    state2 = generate_oauth_state(engine)
    _, user2, is_new2, _ = await oauth_callback(
        adapter=adapter,
        token_engine=engine,
        provider=provider,
        code="code2",
        state=state2,
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
    state = generate_oauth_state(fullauth_with_oauth.token_engine)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "test-code", "state": state},
        )
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data


@pytest.mark.asyncio
async def test_callback_invalid_state(oauth_app):
    transport = ASGITransport(app=oauth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/oauth/mock/callback",
            json={"code": "test-code", "state": "bad-state"},
        )
        assert r.status_code == 400


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
