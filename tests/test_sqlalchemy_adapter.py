"""Integration tests for SQLAlchemyAdapter with a real SQLite database."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import String, event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.dependencies import current_user, require_permission, require_role
from fastapi_fullauth.models.sqlalchemy import (
    OAuthAccountMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    RolePermissionMixin,
    UserMixin,
    UserRoleMixin,
)
from fastapi_fullauth.types import CreateUserSchema
from tests.conftest import UserSchemaWithRoles

# ── Models ──────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


class RefreshToken(RefreshTokenMixin, Base):
    pass


class Role(RoleMixin, Base):
    pass


class UserRole(UserRoleMixin, Base):
    pass


class Permission(PermissionMixin, Base):
    pass


class RolePermission(RolePermissionMixin, Base):
    pass


class OAuthAccount(OAuthAccountMixin, Base):
    pass


class User(UserMixin, Base):
    display_name: Mapped[str] = mapped_column(String(100), default="")
    roles: Mapped[list[Role]] = relationship(secondary="fullauth_user_roles", lazy="selectin")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    # pysqlite/aiosqlite emit BEGIN lazily, which breaks SAVEPOINT and rollback
    # semantics. Apply SQLAlchemy's documented recipe: disable the driver's
    # implicit BEGIN and emit it ourselves.
    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_disable_implicit_begin(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine.sync_engine, "begin")
    def _sqlite_emit_begin(conn):
        conn.exec_driver_sql("BEGIN")

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def adapter(db):
    return SQLAlchemyAdapter(
        session_maker=db,
        user_model=User,
        refresh_token_model=RefreshToken,
        role_model=Role,
        user_role_model=UserRole,
        permission_model=Permission,
        role_permission_model=RolePermission,
        oauth_account_model=OAuthAccount,
        user_schema=UserSchemaWithRoles,
    )


@pytest.fixture
def fullauth(adapter):
    return FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        ),
        adapter=adapter,
    )


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app)

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

    fetched = await adapter.get_user_by_id(user.id)
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
async def test_create_user_duplicate_email_raises(adapter):
    from fastapi_fullauth.exceptions import UserAlreadyExistsError

    data = CreateUserSchema(email="dup@test.com", password="pass123")
    await adapter.create_user(data, hashed_password=hash_password("pass123"))

    with pytest.raises(UserAlreadyExistsError):
        await adapter.create_user(data, hashed_password=hash_password("pass123"))


@pytest.mark.asyncio
async def test_update_user(adapter):
    data = CreateUserSchema(email="upd@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))

    updated = await adapter.update_user(user.id, {"display_name": "Updated"})
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
        token="sa-test-token-123",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc),
        family_id="family-1",
    )
    await adapter.store_refresh_token(token)

    stored = await adapter.get_refresh_token("sa-test-token-123")
    assert stored is not None
    assert stored.revoked is False

    assert await adapter.revoke_refresh_token("sa-test-token-123") is True
    stored = await adapter.get_refresh_token("sa-test-token-123")
    assert stored.revoked is True

    # second revoke returns False (already revoked) = the CAS signal
    assert await adapter.revoke_refresh_token("sa-test-token-123") is False
    assert await adapter.revoke_refresh_token("missing") is False


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
    await adapter.assign_permission_to_role("editor", "posts:create")
    await adapter.assign_permission_to_role("editor", "posts:edit")

    perms = await adapter.get_user_permissions(user.id)
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
        user_id=user.id,
        provider_email="oauth@test.com",
    )
    await adapter.create_oauth_account(account)

    fetched = await adapter.get_oauth_account("github", "gh-456")
    assert fetched is not None

    accounts = await adapter.get_user_oauth_accounts(user.id)
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
async def test_adapter_eager_loads_roles_with_default_lazy_relationship():
    """`_user_query()` adds selectinload on `roles` regardless of the user's
    relationship lazy setting. Without it, accessing `user.roles` outside the
    session in `_to_schema` would raise MissingGreenlet in async mode."""

    class Base2(DeclarativeBase):
        pass

    class RefreshToken2(RefreshTokenMixin, Base2):
        pass

    class Role2(RoleMixin, Base2):
        pass

    class UserRole2(UserRoleMixin, Base2):
        pass

    class User2(UserMixin, Base2):
        roles: Mapped[list[Role2]] = relationship(secondary="fullauth_user_roles")

    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base2.metadata.create_all)
    adapter = SQLAlchemyAdapter(
        session_maker=session_maker,
        user_model=User2,
        refresh_token_model=RefreshToken2,
        role_model=Role2,
        user_role_model=UserRole2,
        user_schema=UserSchemaWithRoles,
    )

    data = CreateUserSchema(email="lazy@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))
    await adapter.assign_role(user.id, "editor")

    fetched = await adapter.get_user_by_email("lazy@test.com")
    assert fetched is not None
    assert "editor" in fetched.roles

    await engine.dispose()


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
    await adapter.assign_role(user.id, "editor")
    assert (await client.get("/role-check", headers=headers)).status_code == 200

    # no permission → 403
    assert (await client.get("/perm-check", headers=headers)).status_code == 403

    # assign permission → 200
    await adapter.assign_permission_to_role("editor", "posts:edit")
    assert (await client.get("/perm-check", headers=headers)).status_code == 200


# ── Transaction tests ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transaction_commits_all_steps(adapter):
    async with adapter.transaction() as tx:
        user = await tx.create_user(
            CreateUserSchema(email="tx@test.com", password="pass123"),
            hashed_password=hash_password("pass123"),
        )
        await tx.assign_role(user.id, "editor")

    fetched = await adapter.get_user_by_email("tx@test.com")
    assert fetched is not None
    assert "editor" in fetched.roles


@pytest.mark.asyncio
async def test_transaction_rolls_back_on_error(adapter):
    class BoomError(Exception):
        pass

    with pytest.raises(BoomError):
        async with adapter.transaction() as tx:
            user = await tx.create_user(
                CreateUserSchema(email="rollback@test.com", password="pass123"),
                hashed_password=hash_password("pass123"),
            )
            await tx.assign_role(user.id, "editor")
            raise BoomError

    assert await adapter.get_user_by_email("rollback@test.com") is None


@pytest.mark.asyncio
async def test_transaction_savepoint_isolates_duplicate(adapter):
    """A unique-constraint violation inside a transaction rolls back only that
    statement; the surrounding transaction stays usable and still commits."""
    from fastapi_fullauth.exceptions import UserAlreadyExistsError

    await adapter.create_user(
        CreateUserSchema(email="exists@test.com", password="pass123"),
        hashed_password=hash_password("pass123"),
    )

    async with adapter.transaction() as tx:
        await tx.create_user(
            CreateUserSchema(email="before@test.com", password="pass123"),
            hashed_password=hash_password("pass123"),
        )
        with pytest.raises(UserAlreadyExistsError):
            await tx.create_user(
                CreateUserSchema(email="exists@test.com", password="pass123"),
                hashed_password=hash_password("pass123"),
            )
        await tx.create_user(
            CreateUserSchema(email="after@test.com", password="pass123"),
            hashed_password=hash_password("pass123"),
        )

    assert await adapter.get_user_by_email("before@test.com") is not None
    assert await adapter.get_user_by_email("after@test.com") is not None


@pytest.mark.asyncio
async def test_transaction_oauth_duplicate_returns_existing(adapter):
    from fastapi_fullauth.types import OAuthAccount

    user = await adapter.create_user(
        CreateUserSchema(email="oauthtx@test.com", password="pass123"),
        hashed_password=hash_password("pass123"),
    )
    account = OAuthAccount(
        provider="github",
        provider_user_id="dup-1",
        user_id=user.id,
        provider_email="oauthtx@test.com",
    )
    await adapter.create_oauth_account(account)

    async with adapter.transaction() as tx:
        again = await tx.create_oauth_account(account)
        assert again.provider_user_id == "dup-1"
        await tx.assign_role(user.id, "editor")

    assert len(await adapter.get_user_oauth_accounts(user.id)) == 1
    fetched = await adapter.get_user_by_email("oauthtx@test.com")
    assert "editor" in fetched.roles


@pytest.mark.asyncio
async def test_transaction_cannot_nest(adapter):
    async with adapter.transaction() as tx:
        with pytest.raises(RuntimeError):
            async with tx.transaction():
                pass
