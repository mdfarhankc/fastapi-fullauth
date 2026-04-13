"""Tests for roles and permissions: RBAC permission system, role assignment,
require_role and require_permission dependencies, and admin permission routes."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.dependencies import require_permission, require_role
from tests.conftest import User


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


async def _make_app():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
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

    @app.get("/admin")
    async def admin(user=Depends(require_role("admin"))):
        return {"msg": "admin", "user": user}

    return app, adapter, fullauth, engine


async def _register_and_login(client, email="user@test.com"):
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "securepass123"},
    )
    return r.json()


async def _make_superuser(client, adapter, email="admin@test.com"):
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "securepass123"},
    )
    tokens = r.json()
    # make superuser
    user = await adapter.get_user_by_email(email)
    await adapter.update_user(user.id, {"is_superuser": True})
    return tokens


# ===========================================================================
# Permission CRUD tests (adapter-level)
# ===========================================================================


@pytest.mark.asyncio
async def test_adapter_permission_crud():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)

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

    await engine.dispose()


@pytest.mark.asyncio
async def test_adapter_get_user_permissions():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)

    # create user with role
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema

    data = CreateUserSchema(email="user@test.com", password="pass")
    user = await adapter.create_user(data, hashed_password=hash_password("pass"))
    await adapter.assign_role(user.id, "editor")
    await adapter.assign_role(user.id, "viewer")

    # assign permissions to roles
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")
    await adapter.assign_permission_to_role("viewer", "posts:read")
    await adapter.assign_permission_to_role("viewer", "posts:edit")  # overlap

    # user permissions should be deduplicated union
    perms = await adapter.get_user_permissions(user.id)
    assert sorted(perms) == ["posts:create", "posts:edit", "posts:read"]

    await engine.dispose()


# ===========================================================================
# require_permission dependency tests
# ===========================================================================


@pytest.mark.asyncio
async def test_require_permission_allows_with_permission():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # assign role + permission
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(user.id, "editor")
        await adapter.assign_permission_to_role("editor", "posts:edit")

        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 200

    await engine.dispose()


@pytest.mark.asyncio
async def test_require_permission_blocks_without_permission():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # assign role but no permissions
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(user.id, "viewer")

        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 403

    await engine.dispose()


@pytest.mark.asyncio
async def test_require_permission_superuser_bypass():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _make_superuser(client, adapter)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # superuser has no roles/permissions but bypasses all checks
        r = await client.get("/perm-check", headers=headers)
        assert r.status_code == 200

    await engine.dispose()


@pytest.mark.asyncio
async def test_require_role_still_works():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # no role → blocked
        r = await client.get("/role-check", headers=headers)
        assert r.status_code == 403

        # assign role → allowed
        user = await adapter.get_user_by_email("user@test.com")
        await adapter.assign_role(user.id, "editor")
        r = await client.get("/role-check", headers=headers)
        assert r.status_code == 200

    await engine.dispose()


# ===========================================================================
# Admin permission routes
# ===========================================================================


@pytest.mark.asyncio
async def test_admin_assign_and_list_permissions():
    app, adapter, fullauth, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_remove_permission():
    app, adapter, fullauth, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_permission_routes_require_superuser():
    app, adapter, fullauth, engine = await _make_app()
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

    await engine.dispose()


# ===========================================================================
# Role assignment and removal (from test_roles.py)
# ===========================================================================


@pytest.mark.asyncio
async def test_assign_role():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # register superuser
        tokens = await _register_and_login(client, "admin@test.com")

        # get user id from adapter
        user = await adapter.get_user_by_email("admin@test.com")
        await adapter.update_user(user.id, {"is_superuser": True})
        admin_headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # register normal user
        tokens2 = await _register_and_login(client, "normal@test.com")
        normal_user = await adapter.get_user_by_email("normal@test.com")

        # normal user can't access /admin
        r = await client.get(
            "/admin",
            headers={"Authorization": f"Bearer {tokens2['access_token']}"},
        )
        assert r.status_code == 403

        # superuser assigns role
        r = await client.post(
            "/api/v1/auth/admin/assign-role",
            json={"user_id": str(normal_user.id), "role": "admin"},
            headers=admin_headers,
        )
        assert r.status_code == 200

        # re-login to get updated token with roles
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "normal@test.com", "password": "securepass123"},
        )
        tokens2 = r.json()

        # now normal user can access /admin
        r = await client.get(
            "/admin",
            headers={"Authorization": f"Bearer {tokens2['access_token']}"},
        )
        assert r.status_code == 200

    await engine.dispose()


@pytest.mark.asyncio
async def test_assign_role_non_superuser_rejected():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client)
        user = await adapter.get_user_by_email("user@test.com")

        r = await client.post(
            "/api/v1/auth/admin/assign-role",
            json={"user_id": str(user.id), "role": "admin"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 403

    await engine.dispose()


@pytest.mark.asyncio
async def test_remove_role():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # create superuser
        tokens = await _register_and_login(client, "super@test.com")
        user = await adapter.get_user_by_email("super@test.com")
        await adapter.update_user(user.id, {"is_superuser": True})
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        # create target user and assign role
        await _register_and_login(client, "target@test.com")
        target = await adapter.get_user_by_email("target@test.com")

        r = await client.post(
            "/api/v1/auth/admin/assign-role",
            json={"user_id": str(target.id), "role": "editor"},
            headers=headers,
        )
        assert r.status_code == 200

        # verify role assigned
        roles = await adapter.get_user_roles(target.id)
        assert "editor" in roles

        # remove role
        r = await client.post(
            "/api/v1/auth/admin/remove-role",
            json={"user_id": str(target.id), "role": "editor"},
            headers=headers,
        )
        assert r.status_code == 200

        # verify role removed
        roles = await adapter.get_user_roles(target.id)
        assert "editor" not in roles

    await engine.dispose()


@pytest.mark.asyncio
async def test_assign_role_user_not_found():
    app, adapter, fullauth, engine = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tokens = await _register_and_login(client, "super@test.com")
        user = await adapter.get_user_by_email("super@test.com")
        await adapter.update_user(user.id, {"is_superuser": True})

        r = await client.post(
            "/api/v1/auth/admin/assign-role",
            json={"user_id": "00000000-0000-0000-0000-000000000000", "role": "admin"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 404

    await engine.dispose()
