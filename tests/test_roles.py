from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import require_role


@pytest.fixture
def role_app():
    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/admin")
    async def admin(user=Depends(require_role("admin"))):
        return {"msg": "admin", "user": user}

    return app, adapter


@pytest.fixture
async def role_client(role_app):
    app, _ = role_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _register_and_login(client, email="user@test.com"):
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": "securepass123"},
    )
    return r.json()


async def _make_superuser(adapter, user_id):
    adapter._users[user_id]["is_superuser"] = True


@pytest.mark.asyncio
async def test_assign_role(role_client, role_app):
    _, adapter = role_app

    # register superuser
    tokens = await _register_and_login(role_client, "admin@test.com")

    # get user id from adapter
    user = await adapter.get_user_by_email("admin@test.com")
    await _make_superuser(adapter, user.id)
    admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # register normal user
    tokens2 = await _register_and_login(role_client, "normal@test.com")
    normal_user = await adapter.get_user_by_email("normal@test.com")

    # normal user can't access /admin
    r = await role_client.get(
        "/admin",
        headers={"Authorization": f"Bearer {tokens2['access_token']}"},
    )
    assert r.status_code == 403

    # superuser assigns role
    r = await role_client.post(
        "/api/v1/auth/admin/assign-role",
        json={"user_id": normal_user.id, "role": "admin"},
        headers=admin_headers,
    )
    assert r.status_code == 200

    # re-login to get updated token with roles
    tokens2 = await _register_and_login(role_client, "normal@test.com")
    # user already exists, just login
    r = await role_client.post(
        "/api/v1/auth/login",
        data={"username": "normal@test.com", "password": "securepass123"},
    )
    tokens2 = r.json()

    # now normal user can access /admin
    r = await role_client.get(
        "/admin",
        headers={"Authorization": f"Bearer {tokens2['access_token']}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_assign_role_non_superuser_rejected(role_client, role_app):
    _, adapter = role_app
    tokens = await _register_and_login(role_client)
    user = await adapter.get_user_by_email("user@test.com")

    r = await role_client.post(
        "/api/v1/auth/admin/assign-role",
        json={"user_id": user.id, "role": "admin"},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_remove_role(role_client, role_app):
    _, adapter = role_app

    # create superuser
    tokens = await _register_and_login(role_client, "super@test.com")
    user = await adapter.get_user_by_email("super@test.com")
    await _make_superuser(adapter, user.id)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # create target user and assign role
    await _register_and_login(role_client, "target@test.com")
    target = await adapter.get_user_by_email("target@test.com")

    r = await role_client.post(
        "/api/v1/auth/admin/assign-role",
        json={"user_id": target.id, "role": "editor"},
        headers=headers,
    )
    assert r.status_code == 200

    # verify role assigned
    roles = await adapter.get_user_roles(target.id)
    assert "editor" in roles

    # remove role
    r = await role_client.post(
        "/api/v1/auth/admin/remove-role",
        json={"user_id": target.id, "role": "editor"},
        headers=headers,
    )
    assert r.status_code == 200

    # verify role removed
    roles = await adapter.get_user_roles(target.id)
    assert "editor" not in roles


@pytest.mark.asyncio
async def test_assign_role_user_not_found(role_client, role_app):
    _, adapter = role_app
    tokens = await _register_and_login(role_client, "super@test.com")
    user = await adapter.get_user_by_email("super@test.com")
    await _make_superuser(adapter, user.id)

    r = await role_client.post(
        "/api/v1/auth/admin/assign-role",
        json={"user_id": "nonexistent", "role": "admin"},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 404
