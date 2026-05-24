"""Tests for profile and account management: change password, update profile,
and delete account."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from tests.conftest import make_test_adapter


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


async def _make_app(**fullauth_kwargs):
    engine, session_maker = await _make_db()
    adapter = make_test_adapter(session_maker)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
        **fullauth_kwargs,
    )
    app = FastAPI()
    fullauth.init_app(app)
    return app, adapter, fullauth, engine


async def _register_and_login(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "t@t.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "t@t.com", "password": "securepass123"},
    )
    return r.json()


# Change password


@pytest.mark.asyncio
async def test_change_password():
    app, adapter, _, engine = await _make_app()
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
            json={"email": "t@t.com", "password": "newpass456!!"},
        )
        assert r.status_code == 200

    await engine.dispose()


@pytest.mark.asyncio
async def test_change_password_wrong_current():
    app, _, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_change_password_weak_new():
    app, _, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_change_password_for_user_without_stored_hash():
    """OAuth-only users have hashed_password=NULL. They must be able to set a first
    password through /change-password without supplying `current_password`."""
    from fastapi_fullauth.types import CreateUserSchema

    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a user the way the OAuth flow does = no stored password.
        data = CreateUserSchema(email="oauth@t.com", password="placeholder-unused")
        user = await adapter.create_user(data, hashed_password=None)
        assert await adapter.get_hashed_password(user.id) is None

        # Mint an access token directly so we can call /change-password authenticated.
        access = fullauth.token_engine.create_access_token(user_id=str(user.id))
        headers = {"Authorization": f"Bearer {access}"}

        r = await client.post(
            "/api/v1/auth/change-password",
            json={"new_password": "firstpassword42"},
            headers=headers,
        )
        assert r.status_code == 200

        # New password works for login.
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "oauth@t.com", "password": "firstpassword42"},
        )
        assert r.status_code == 200

    await engine.dispose()


@pytest.mark.asyncio
async def test_change_password_still_requires_current_when_hash_exists():
    """Regression: a user with a stored hash can't bypass current-password check
    by omitting the field. Otherwise stolen access tokens would silently overwrite
    passwords without the current-password defence."""
    app, _, _, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.post(
            "/api/v1/auth/change-password",
            json={"new_password": "newpass456!!"},
            headers=headers,
        )
        assert r.status_code == 400

    await engine.dispose()


# Update profile


@pytest.mark.asyncio
async def test_update_profile():
    from fastapi_fullauth.types import CreateUserSchema, UserSchema

    class MyCreate(CreateUserSchema):
        display_name: str = ""

    class MyUser(UserSchema):
        display_name: str = ""

    engine, session_maker = await _make_db()
    adapter = make_test_adapter(
        session_maker,
        user_schema=MyUser,
        create_user_schema=MyCreate,
    )
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123", "display_name": "Old"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

        r = await client.patch(
            "/api/v1/auth/me",
            json={"display_name": "New Name"},
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["display_name"] == "New Name"

    await engine.dispose()


@pytest.mark.asyncio
async def test_update_profile_rejects_unknown_fields():
    app, _, _, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.patch(
            "/api/v1/auth/me",
            json={"nonexistent_field": "value"},
            headers=headers,
        )
        assert r.status_code == 422
        assert "Unknown fields" in r.json()["detail"]

    await engine.dispose()


@pytest.mark.asyncio
async def test_update_profile_rejects_protected_fields():
    app, _, _, engine = await _make_app()
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

    await engine.dispose()


# Delete account


@pytest.mark.asyncio
async def test_delete_account():
    app, adapter, _, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        r = await client.delete("/api/v1/auth/me", headers=headers)
        assert r.status_code == 204

        # user should be gone
        user = await adapter.get_user_by_email("t@t.com")
        assert user is None

    await engine.dispose()
