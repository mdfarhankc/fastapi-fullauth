"""Tests for event hooks: after_register, after_login, after_logout,
send_password_reset_email, and send_verification_email callbacks."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from tests.conftest import User


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


# ===========================================================================
# Lifecycle hooks (register, login, logout)
# ===========================================================================


@pytest.fixture
def hook_log():
    return []


@pytest.fixture
async def hooks_app(hook_log):
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)

    async def on_register(user):
        hook_log.append(("register", user.email))

    async def on_login(user):
        hook_log.append(("login", user.email))

    async def on_logout(user_id):
        hook_log.append(("logout", user_id))

    fullauth.hooks.on("after_register", on_register)
    fullauth.hooks.on("after_login", on_login)
    fullauth.hooks.on("after_logout", on_logout)

    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)
    yield app
    await engine.dispose()


@pytest.fixture
async def hooks_client(hooks_app):
    transport = ASGITransport(app=hooks_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_hooks_fire_on_register(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    assert ("register", "hook@test.com") in hook_log


@pytest.mark.asyncio
async def test_hooks_fire_on_login(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    await hooks_client.post(
        "/api/v1/auth/login",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    assert ("login", "hook@test.com") in hook_log


@pytest.mark.asyncio
async def test_hooks_fire_on_logout(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    r = await hooks_client.post(
        "/api/v1/auth/login",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    token = r.json()["access_token"]
    await hooks_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert any(event == "logout" for event, _ in hook_log)


# ===========================================================================
# Password reset email callback
# ===========================================================================


@pytest.mark.asyncio
async def test_password_reset_email_callback():
    sent = []

    async def on_reset_email(email: str, token: str):
        sent.append({"email": email, "token": token})

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)
    fullauth.hooks.on("send_password_reset_email", on_reset_email)
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # register a user first
        await client.post(
            "/api/v1/auth/register",
            json={"email": "reset@test.com", "password": "securepass123"},
        )

        # request reset
        r = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "reset@test.com"},
        )
        assert r.status_code == 202
        assert len(sent) == 1
        assert sent[0]["email"] == "reset@test.com"
        assert sent[0]["token"]  # token should be non-empty

    await engine.dispose()


# ===========================================================================
# Email callback via hooks (password reset)
# ===========================================================================


@pytest.mark.asyncio
async def test_email_callback_via_hooks():
    """Register email callback via hooks.on() instead of constructor param."""
    sent = []

    async def on_reset(email, token):
        sent.append({"email": email, "token": token})

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
    )
    fullauth.hooks.on("send_password_reset_email", on_reset)

    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "hook@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "hook@test.com"},
        )
        assert r.status_code == 202
        assert len(sent) == 1
        assert sent[0]["email"] == "hook@test.com"

    await engine.dispose()
