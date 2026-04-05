"""Tests for change-password, update profile, delete account, expires_in, auth rate limiting."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter


def _make_app(**fullauth_kwargs):
    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
        **fullauth_kwargs,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)
    return app, adapter, fullauth


async def _register_and_login(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "t@t.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "t@t.com", "password": "securepass123"},
    )
    return r.json()


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "securepass123", "new_password": "newpass456!!"},
            headers=headers,
        )
        assert r.status_code == 200

        # can login with new password
        r = await client.post(
            "/api/v1/auth/login",
            data={"username": "t@t.com", "password": "newpass456!!"},
        )
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_change_password_wrong_current():
    app, _, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "wrongpass", "new_password": "newpass456!!"},
            headers=headers,
        )
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_change_password_weak_new():
    app, _, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "securepass123", "new_password": "short"},
            headers=headers,
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Update profile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_profile():
    from fastapi_fullauth.types import CreateUserSchema, UserSchema

    class MyCreate(CreateUserSchema):
        display_name: str = ""

    class MyUser(UserSchema):
        display_name: str = ""

    adapter = InMemoryAdapter(user_schema=MyUser)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
        create_user_schema=MyCreate,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123", "display_name": "Old"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            data={"username": "t@t.com", "password": "securepass123"},
        )
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

        r = await client.patch(
            "/api/v1/auth/me",
            json={"display_name": "New Name"},
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["display_name"] == "New Name"


@pytest.mark.asyncio
async def test_update_profile_rejects_protected_fields():
    app, _, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.patch(
            "/api/v1/auth/me",
            json={"is_superuser": True},
            headers=headers,
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Delete account
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_account():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.delete("/api/v1/auth/me", headers=headers)
        assert r.status_code == 204

        # user should be gone
        user = await adapter.get_user_by_email("t@t.com")
        assert user is None


# ---------------------------------------------------------------------------
# expires_in in token response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_returns_expires_in():
    app, _, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        assert "expires_in" in tokens
        assert tokens["expires_in"] == 30 * 60  # default 30 minutes


@pytest.mark.asyncio
async def test_refresh_returns_expires_in():
    app, _, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert r.status_code == 200
        assert r.json()["expires_in"] == 30 * 60


# ---------------------------------------------------------------------------
# Auth route rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rate_limited():
    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=True,
            AUTH_RATE_LIMIT_LOGIN=2,
            AUTH_RATE_LIMIT_WINDOW_SECONDS=60,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )

        # first 2 login attempts should work (even if wrong password)
        for _ in range(2):
            await client.post(
                "/api/v1/auth/login",
                data={"username": "t@t.com", "password": "securepass123"},
            )

        # 3rd should be rate limited
        r = await client.post(
            "/api/v1/auth/login",
            data={"username": "t@t.com", "password": "securepass123"},
        )
        assert r.status_code == 429


@pytest.mark.asyncio
async def test_register_rate_limited():
    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=True,
            AUTH_RATE_LIMIT_REGISTER=1,
            AUTH_RATE_LIMIT_WINDOW_SECONDS=60,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "a@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "b@t.com", "password": "securepass123"},
        )
        assert r.status_code == 429
