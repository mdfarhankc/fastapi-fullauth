"""Integration tests for SQLAlchemyAdapter with a real SQLite database."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlalchemy import (
    FullAuthBase,
    RefreshTokenModel,
    RoleModel,
    SQLAlchemyAdapter,
    UserBase,
)
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.dependencies import current_user, require_permission, require_role
from fastapi_fullauth.types import CreateUserSchema

# ── Models ──────────────────────────────────────────────────────────


class User(UserBase, FullAuthBase):
    __tablename__ = "fullauth_users"

    display_name: Mapped[str] = mapped_column(String(100), default="")
    roles: Mapped[list[RoleModel]] = relationship(secondary="fullauth_user_roles", lazy="selectin")
    refresh_tokens: Mapped[list[RefreshTokenModel]] = relationship(lazy="noload")


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(FullAuthBase.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def adapter(db):
    return SQLAlchemyAdapter(session_maker=db, user_model=User)


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

    fetched = await adapter.get_user_by_id(str(user.id))
    assert fetched is not None
    assert fetched.email == "test@test.com"


@pytest.mark.asyncio
async def test_get_user_by_email(adapter):
    data = CreateUserSchema(email="find@test.com", password="pass123")
    await adapter.create_user(data, hashed_password=hash_password("pass123"))

    user = await adapter.get_user_by_email("find@test.com")
    assert user is not None
    assert await adapter.get_user_by_email("nope@test.com") is None


@pytest.mark.asyncio
async def test_update_user(adapter):
    data = CreateUserSchema(email="upd@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    updated = await adapter.update_user(str(user.id), {"display_name": "Updated"})
    assert updated.email == "upd@test.com"


@pytest.mark.asyncio
async def test_delete_user(adapter):
    data = CreateUserSchema(email="del@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.delete_user(str(user.id))
    assert await adapter.get_user_by_id(str(user.id)) is None


@pytest.mark.asyncio
async def test_password_operations(adapter):
    data = CreateUserSchema(email="pw@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    hashed = await adapter.get_hashed_password(str(user.id))
    assert hashed is not None

    await adapter.set_password(str(user.id), hash_password("newpass"))
    new_hashed = await adapter.get_hashed_password(str(user.id))
    assert new_hashed != hashed


@pytest.mark.asyncio
async def test_set_user_verified(adapter):
    data = CreateUserSchema(email="verify@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.set_user_verified(str(user.id))
    user = await adapter.get_user_by_id(str(user.id))
    assert user.is_verified is True


# ── Role tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assign_and_get_roles(adapter):
    data = CreateUserSchema(email="role@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.assign_role(str(user.id), "editor")
    await adapter.assign_role(str(user.id), "viewer")

    roles = await adapter.get_user_roles(str(user.id))
    assert sorted(roles) == ["editor", "viewer"]


@pytest.mark.asyncio
async def test_remove_role(adapter):
    data = CreateUserSchema(email="rmrole@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    await adapter.assign_role(str(user.id), "editor")
    await adapter.assign_role(str(user.id), "viewer")
    await adapter.remove_role(str(user.id), "editor")

    roles = await adapter.get_user_roles(str(user.id))
    assert roles == ["viewer"]


# ── Refresh token tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_token_crud(adapter):
    from datetime import datetime, timezone

    from fastapi_fullauth.types import RefreshToken

    data = CreateUserSchema(email="rt@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    token = RefreshToken(
        token="sa-test-token-123",
        user_id=str(user.id),
        expires_at=datetime.now(timezone.utc),
        family_id="family-1",
    )
    await adapter.store_refresh_token(token)

    stored = await adapter.get_refresh_token("sa-test-token-123")
    assert stored is not None
    assert stored.revoked is False

    await adapter.revoke_refresh_token("sa-test-token-123")
    stored = await adapter.get_refresh_token("sa-test-token-123")
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

    await adapter.assign_role(str(user.id), "editor")
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")

    perms = await adapter.get_user_permissions(str(user.id))
    assert sorted(perms) == ["posts:create", "posts:edit"]


# ── OAuth tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oauth_account_crud(adapter):
    from fastapi_fullauth.types import OAuthAccount

    data = CreateUserSchema(email="oauth@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    account = OAuthAccount(
        provider="github",
        provider_user_id="gh-456",
        user_id=str(user.id),
        provider_email="oauth@test.com",
    )
    await adapter.create_oauth_account(account)

    fetched = await adapter.get_oauth_account("github", "gh-456")
    assert fetched is not None

    accounts = await adapter.get_user_oauth_accounts(str(user.id))
    assert len(accounts) == 1

    await adapter.delete_oauth_account("github", "gh-456")
    assert await adapter.get_oauth_account("github", "gh-456") is None


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

    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r.status_code == 200
    assert r.json()["refresh_token"] != old_refresh

    # old token rejected
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
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

    # no role → 403
    assert (await client.get("/role-check", headers=headers)).status_code == 403

    # assign role → 200
    await adapter.assign_role(str(user.id), "editor")
    assert (await client.get("/role-check", headers=headers)).status_code == 200

    # no permission → 403
    assert (await client.get("/perm-check", headers=headers)).status_code == 403

    # assign permission → 200
    await adapter.assign_permission_to_role("editor", "posts:edit")
    assert (await client.get("/perm-check", headers=headers)).status_code == 200
