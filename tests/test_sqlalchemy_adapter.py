"""Integration tests for SQLAlchemyAdapter with a real SQLite database.

Defines its own concrete SQLAlchemy models and DB lifecycle, overriding the
SQLModel-based conftest ``db`` / ``adapter`` fixtures; the shared contract
runs via the AdapterConformance subclass below.
"""

import pytest
from sqlalchemy import String, Text, event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.models.sqlalchemy import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    RolePermissionMixin,
    UserMixin,
    UserRoleMixin,
)
from fastapi_fullauth.types import CreateUserSchema
from tests.adapter_conformance import AdapterConformance
from tests.conftest import UserSchemaWithRoles

# --- Models ------------------------------------------------------------


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


class Passkey(PasskeyMixin, Base):
    pass


class User(UserMixin, Base):
    display_name: Mapped[str] = mapped_column(String(100), default="")
    roles: Mapped[list[Role]] = relationship(secondary="fullauth_user_roles", lazy="selectin")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")


# --- Fixtures ----------------------------------------------------------


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
        passkey_model=Passkey,
        user_schema=UserSchemaWithRoles,
    )


# --- Shared conformance suite ------------------------------------------


class TestSQLAlchemyAdapterConformance(AdapterConformance):
    pass


# --- Adapter-specific tests --------------------------------------------


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


# --- Schema parity with the SQLModel mixins ----------------------------


def test_sqlalchemy_role_permission_name_have_length_and_index():
    """Role/Permission.name must declare an explicit VARCHAR length and index to
    match the SQLModel mixins; an unbounded VARCHAR unique key fails DDL on MySQL."""
    role_name = Role.__table__.c.name
    perm_name = Permission.__table__.c.name
    assert isinstance(role_name.type, String) and role_name.type.length == 100
    assert isinstance(perm_name.type, String) and perm_name.type.length == 200
    assert role_name.index is True
    assert perm_name.index is True


def test_sqlalchemy_oauth_token_columns_are_text():
    """OAuth access/refresh tokens must be Text, never a length-capped VARCHAR
    that would truncate long provider tokens on MySQL."""
    assert isinstance(OAuthAccount.__table__.c.access_token.type, Text)
    assert isinstance(OAuthAccount.__table__.c.refresh_token.type, Text)


def test_sqlalchemy_refresh_token_is_length_capped_varchar():
    """The refresh-token `token` is uniquely indexed, so it must be a bounded
    VARCHAR (MySQL can't uniquely index TEXT) wide enough not to truncate a
    refresh JWT. Mirrors the SQLModel mixin."""
    col = RefreshToken.__table__.c.token
    assert isinstance(col.type, String) and col.type.length == 512
    assert col.unique is True
    assert col.index is True
