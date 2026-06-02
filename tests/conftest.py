import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import Field, Relationship, SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig, UserSchema
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.dependencies import current_user
from fastapi_fullauth.models.sqlmodel import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    RolePermissionMixin,
    UserMixin,
    UserRoleMixin,
)


class UserSchemaWithRoles(UserSchema):
    roles: list[str] = Field(default_factory=list)

    PROTECTED_FIELDS = UserSchema.PROTECTED_FIELDS | {"roles"}


class RefreshToken(RefreshTokenMixin, table=True):
    __table_args__ = {"extend_existing": True}


class UserRole(UserRoleMixin, table=True):
    __table_args__ = {"extend_existing": True}


class Role(RoleMixin, table=True):
    __table_args__ = {"extend_existing": True}


class RolePermission(RolePermissionMixin, table=True):
    __table_args__ = {"extend_existing": True}


class Permission(PermissionMixin, table=True):
    __table_args__ = {"extend_existing": True}


class OAuthAccount(OAuthAccountMixin, table=True):
    pass


class Passkey(PasskeyMixin, table=True):
    pass


class User(UserMixin, table=True):
    __table_args__ = {"extend_existing": True}

    display_name: str = Field(default="", max_length=100)
    roles: list[Role] = Relationship(link_model=UserRole)
    refresh_tokens: list[RefreshToken] = Relationship(cascade_delete=True)


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
        await conn.run_sync(SQLModel.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def config():
    return FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
    )


def make_test_adapter(session_maker, **overrides):
    defaults = {
        "user_model": User,
        "refresh_token_model": RefreshToken,
        "role_model": Role,
        "user_role_model": UserRole,
        "permission_model": Permission,
        "role_permission_model": RolePermission,
        "oauth_account_model": OAuthAccount,
        "passkey_model": Passkey,
        "user_schema": UserSchemaWithRoles,
    }
    return SQLModelAdapter(session_maker=session_maker, **{**defaults, **overrides})


@pytest.fixture
def adapter(db):
    return make_test_adapter(db)


@pytest.fixture
def fullauth(config, adapter):
    return FullAuth(config=config, adapter=adapter)


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return user

    return app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def registered_user(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    return r.json()


@pytest.fixture
async def auth_headers(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    tokens = r.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
async def login_tokens(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    return r.json()
