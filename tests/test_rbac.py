"""Tests for RBAC permission system."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import require_permission, require_role


def _make_app():
    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/role-check")
    async def role_check(user=Depends(require_role("editor"))):
        return {"user_id": str(user.id)}

    @app.get("/perm-check")
    async def perm_check(user=Depends(require_permission("posts:edit"))):
        return {"user_id": str(user.id)}

    return app, adapter, fullauth


async def _register_and_login(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    tokens = r.json()
    return tokens


async def _make_superuser(client, adapter):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "admin@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@test.com", "password": "securepass123"},
    )
    tokens = r.json()
    # make superuser
    user = await adapter.get_user_by_email("admin@test.com")
    await adapter.update_user(str(user.id), {"is_superuser": True})
    return tokens


# ── InMemoryAdapter permission tests ────────────────────────────────


@pytest.mark.asyncio
async def test_memory_adapter_permission_crud():
    adapter = InMemoryAdapter()

    # initially empty
    perms = await adapter.get_role_permissions("editor")
    assert perms == []

    # assign permissions
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")
    perms = await adapter.get_role_permissions("editor")
    assert sorted(perms) == ["posts:create", "posts:edit"]

    # duplicate assignment is idempotent
    await adapter.assign_permission_to_role("editor", "posts:create")
    perms = await adapter.get_role_permissions("editor")
    assert sorted(perms) == ["posts:create", "posts:edit"]

    # remove permission
    await adapter.remove_permission_from_role("editor", "posts:create")
    perms = await adapter.get_role_permissions("editor")
    assert perms == ["posts:edit"]

    # remove non-existent is a no-op
    await adapter.remove_permission_from_role("editor", "posts:delete")
    perms = await adapter.get_role_permissions("editor")
    assert perms == ["posts:edit"]


@pytest.mark.asyncio
async def test_memory_adapter_get_user_permissions():
    adapter = InMemoryAdapter()

    # create user with role
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema

    data = CreateUserSchema(email="user@test.com", password="pass")
    user = await adapter.create_user(data, hashed_password=hash_password("pass"))
    await adapter.assign_role(str(user.id), "editor")
    await adapter.assign_role(str(user.id), "viewer")

    # assign permissions to roles
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")
    await adapter.assign_permission_to_role("viewer", "posts:read")
    await adapter.assign_permission_to_role("viewer", "posts:edit")  # overlap

    # user permissions should be deduplicated union
    perms = await adapter.get_user_permissions(str(user.id))
    assert sorted(perms) == ["posts:create", "posts:edit", "posts:read"]


# ── require_permission dependency tests ─────────────────────────────


@pytest.mark.asyncio
async def test_require_permission_allows_with_permission():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # assign role + permission
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(str(user.id), "editor")
        await adapter.assign_permission_to_role("editor", "posts:edit")

        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_require_permission_blocks_without_permission():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # assign role but no permissions
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(str(user.id), "viewer")

        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_require_permission_superuser_bypass():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _make_superuser(client, adapter)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # superuser has no roles/permissions but bypasses all checks
        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_require_role_still_works():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # no role → blocked
        r = await client.get("/role-check", headers=headers)
        assert r.status_code == 403

        # assign role → allowed
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(str(user.id), "editor")
        r = await client.get("/role-check", headers=headers)
        assert r.status_code == 200


# ── Admin permission routes ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_admin_assign_and_list_permissions():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _make_superuser(client, adapter)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # assign permission to role
        r = await client.post(
            "/api/v1/auth/admin/assign-permission",
            json={"role": "editor", "permission": "posts:create"},
            headers=headers,
        )
        assert r.status_code == 200

        r = await client.post(
            "/api/v1/auth/admin/assign-permission",
            json={"role": "editor", "permission": "posts:edit"},
            headers=headers,
        )
        assert r.status_code == 200

        # list permissions
        r = await client.get(
            "/api/v1/auth/admin/role-permissions/editor",
            headers=headers,
        )
        assert r.status_code == 200
        assert sorted(r.json()) == ["posts:create", "posts:edit"]


@pytest.mark.asyncio
async def test_admin_remove_permission():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _make_superuser(client, adapter)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # setup
        await adapter.assign_permission_to_role("editor", "posts:create")
        await adapter.assign_permission_to_role("editor", "posts:edit")

        # remove one
        r = await client.post(
            "/api/v1/auth/admin/remove-permission",
            json={"role": "editor", "permission": "posts:create"},
            headers=headers,
        )
        assert r.status_code == 200

        # verify
        r = await client.get(
            "/api/v1/auth/admin/role-permissions/editor",
            headers=headers,
        )
        assert r.json() == ["posts:edit"]


@pytest.mark.asyncio
async def test_admin_permission_routes_require_superuser():
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # regular user cannot access permission routes
        r = await client.post(
            "/api/v1/auth/admin/assign-permission",
            json={"role": "editor", "permission": "posts:edit"},
            headers=headers,
        )
        assert r.status_code == 403

        r = await client.get(
            "/api/v1/auth/admin/role-permissions/editor",
            headers=headers,
        )
        assert r.status_code == 403
