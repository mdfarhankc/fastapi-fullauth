"""Integration tests for SQLModelAdapter with a real SQLite database."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord  # noqa: F401
from fastapi_fullauth.adapters.sqlmodel.models.permission import (  # noqa: F401
    Permission,
    RolePermissionLink,
)
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.dependencies import current_user, require_permission, require_role
from fastapi_fullauth.types import CreateUserSchema
from tests.conftest import User, UserSchemaWithRoles

# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def adapter(db):
    return SQLModelAdapter(session_maker=db, user_model=User, user_schema=UserSchemaWithRoles)


@pytest.fixture
def fullauth(adapter):
    return FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
    )


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return user

    @app.get("/role-check")
    async def role_check(user=Depends(require_role("editor"))):
        return {"ok": True}

    @app.get("/perm-check")
    async def perm_check(user=Depends(require_permission("posts:edit"))):
        return {"ok": True}

    return app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Adapter CRUD tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_and_get_user(adapter):
    data = CreateUserSchema(email="test@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))
    assert user.email == "test@test.com"
    assert user.is_active is True
    assert user.roles == []

    fetched = await adapter.get_user_by_id(user.id)
    assert fetched is not None
    assert fetched.email == "test@test.com"


@pytest.mark.asyncio
async def test_get_user_by_email(adapter):
    data = CreateUserSchema(email="find@test.com", password="pass123")
    await adapter.create_user(data, hashed_password=hash_password("pass123"))

    user = await adapter.get_user_by_email("find@test.com")
    assert user is not None
    assert user.email == "find@test.com"

    assert await adapter.get_user_by_email("nope@test.com") is None


@pytest.mark.asyncio
async def test_create_user_duplicate_email_raises(adapter):
    from fastapi_fullauth.exceptions import UserAlreadyExistsError

    data = CreateUserSchema(email="dup@test.com", password="pass123")
    await adapter.create_user(data, hashed_password=hash_password("pass123"))

    with pytest.raises(UserAlreadyExistsError):
        await adapter.create_user(data, hashed_password=hash_password("pass123"))


@pytest.mark.asyncio
async def test_get_user_by_field(adapter):
    data = CreateUserSchema(email="field@test.com", password="pass123")
    await adapter.create_user(data, hashed_password=hash_password("pass123"))

    user = await adapter.get_user_by_field("email", "field@test.com")
    assert user is not None


@pytest.mark.asyncio
async def test_update_user(adapter):
    data = CreateUserSchema(email="upd@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    updated = await adapter.update_user(user.id, {"display_name": "Updated Name"})
    assert updated.email == "upd@test.com"


@pytest.mark.asyncio
async def test_delete_user(adapter):
    data = CreateUserSchema(email="del@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.delete_user(user.id)
    assert await adapter.get_user_by_id(user.id) is None


@pytest.mark.asyncio
async def test_password_operations(adapter):
    data = CreateUserSchema(email="pw@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    hashed = await adapter.get_hashed_password(user.id)
    assert hashed is not None

    await adapter.set_password(user.id, hash_password("newpass"))
    new_hashed = await adapter.get_hashed_password(user.id)
    assert new_hashed != hashed


@pytest.mark.asyncio
async def test_set_user_verified(adapter):
    data = CreateUserSchema(email="verify@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))
    assert user.is_verified is False

    await adapter.set_user_verified(user.id)
    user = await adapter.get_user_by_id(user.id)
    assert user.is_verified is True


# ── Role tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assign_and_get_roles(adapter):
    data = CreateUserSchema(email="role@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.assign_role(user.id, "editor")
    await adapter.assign_role(user.id, "viewer")

    roles = await adapter.get_user_roles(user.id)
    assert sorted(roles) == ["editor", "viewer"]


@pytest.mark.asyncio
async def test_remove_role(adapter):
    data = CreateUserSchema(email="rmrole@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.assign_role(user.id, "editor")
    await adapter.assign_role(user.id, "viewer")
    await adapter.remove_role(user.id, "editor")

    roles = await adapter.get_user_roles(user.id)
    assert roles == ["viewer"]


# ── Refresh token tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_token_crud(adapter):
    from datetime import datetime, timezone

    from fastapi_fullauth.types import RefreshToken

    data = CreateUserSchema(email="rt@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    token = RefreshToken(
        token="test-token-123",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc),
        family_id="family-1",
        revoked=False,
    )
    await adapter.store_refresh_token(token)

    stored = await adapter.get_refresh_token("test-token-123")
    assert stored is not None
    assert stored.family_id == "family-1"
    assert stored.revoked is False

    assert await adapter.revoke_refresh_token("test-token-123") is True
    stored = await adapter.get_refresh_token("test-token-123")
    assert stored.revoked is True

    # second revoke returns False — already revoked (the CAS signal)
    assert await adapter.revoke_refresh_token("test-token-123") is False

    # revoking an unknown token also returns False
    assert await adapter.revoke_refresh_token("does-not-exist") is False


@pytest.mark.asyncio
async def test_revoke_refresh_token_family(adapter):
    from datetime import datetime, timezone

    from fastapi_fullauth.types import RefreshToken

    data = CreateUserSchema(email="rtf@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))
    for i in range(3):
        await adapter.store_refresh_token(
            RefreshToken(
                token=f"family-token-{i}",
                user_id=user.id,
                expires_at=datetime.now(timezone.utc),
                family_id="same-family",
            )
        )

    await adapter.revoke_refresh_token_family("same-family")

    for i in range(3):
        stored = await adapter.get_refresh_token(f"family-token-{i}")
        assert stored.revoked is True


# ── Permission tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_permission_crud(adapter):
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")

    perms = await adapter.get_role_permissions("editor")
    assert sorted(perms) == ["posts:create", "posts:edit"]

    await adapter.remove_permission_from_role("editor", "posts:create")
    perms = await adapter.get_role_permissions("editor")
    assert perms == ["posts:edit"]


@pytest.mark.asyncio
async def test_user_permissions_through_roles(adapter):
    data = CreateUserSchema(email="perms@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.assign_role(user.id, "editor")
    await adapter.assign_role(user.id, "viewer")
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")
    await adapter.assign_permission_to_role("viewer", "posts:read")

    perms = await adapter.get_user_permissions(user.id)
    assert sorted(perms) == ["posts:create", "posts:edit", "posts:read"]


# ── OAuth tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth_account_crud(adapter):
    from fastapi_fullauth.types import OAuthAccount

    data = CreateUserSchema(email="oauth@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    account = OAuthAccount(
        provider="google",
        provider_user_id="g-123",
        user_id=user.id,
        provider_email="oauth@test.com",
    )
    await adapter.create_oauth_account(account)

    fetched = await adapter.get_oauth_account("google", "g-123")
    assert fetched is not None
    assert fetched.provider_email == "oauth@test.com"

    accounts = await adapter.get_user_oauth_accounts(user.id)
    assert len(accounts) == 1

    updated = await adapter.update_oauth_account("google", "g-123", {"access_token": "new-token"})
    assert updated.access_token == "new-token"

    await adapter.delete_oauth_account("google", "g-123")
    assert await adapter.get_oauth_account("google", "g-123") is None


# ── Full flow via HTTP ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_register_login_me_flow(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "flow@test.com", "password": "securepass123"},
    )
    assert r.status_code == 201

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "flow@test.com", "password": "securepass123"},
    )
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    r = await client.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["email"] == "flow@test.com"


@pytest.mark.asyncio
async def test_refresh_token_rotation(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "rot@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "rot@test.com", "password": "securepass123"},
    )
    old_refresh = r.json()["refresh_token"]

    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert r.status_code == 200
    new_refresh = r.json()["refresh_token"]
    assert new_refresh != old_refresh

    # old token should be rejected
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_role_and_permission_flow(client, adapter):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "rbac@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "rbac@test.com", "password": "securepass123"},
    )
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    user = await adapter.get_user_by_email("rbac@test.com")

    # no role → blocked
    r = await client.get("/role-check", headers=headers)
    assert r.status_code == 403

    # assign role → allowed
    await adapter.assign_role(user.id, "editor")
    r = await client.get("/role-check", headers=headers)
    assert r.status_code == 200

    # no permission → blocked
    r = await client.get("/perm-check", headers=headers)
    assert r.status_code == 403

    # assign permission → allowed
    await adapter.assign_permission_to_role("editor", "posts:edit")
    r = await client.get("/perm-check", headers=headers)
    assert r.status_code == 200
