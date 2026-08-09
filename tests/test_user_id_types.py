"""Tests for pluggable user id types.

Covers integer and string primary keys end to end, the schema/model mismatch
guard, and that a malformed token subject is rejected as a 401 at every site
that converts one.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import UniqueConstraint, event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7

from fastapi_fullauth import CreateUserSchema, FullAuth, FullAuthConfig, UserSchema
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from tests.adapter_conformance import AdapterConformance

SECRET = "test-secret-key-that-is-long-enough-32b"


# ── Models keyed by int and str ─────────────────────────────────────


class IntUser(SQLModel, table=True):
    __tablename__ = "intkey_users"
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    display_name: str = Field(default="", max_length=100)


class IntRefreshToken(SQLModel, table=True):
    __tablename__ = "intkey_refresh_tokens"
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True, max_length=512)
    user_id: int = Field(foreign_key="intkey_users.id", ondelete="CASCADE")
    expires_at: datetime
    family_id: str = Field(index=True)
    revoked: bool = False
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StrUser(SQLModel, table=True):
    __tablename__ = "strkey_users"
    id: str = Field(default_factory=lambda: uuid4().hex, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False


class StrRefreshToken(SQLModel, table=True):
    __tablename__ = "strkey_refresh_tokens"
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True, max_length=512)
    user_id: str = Field(foreign_key="strkey_users.id", ondelete="CASCADE")
    expires_at: datetime
    family_id: str = Field(index=True)
    revoked: bool = False
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntOAuthAccount(SQLModel, table=True):
    __tablename__ = "intkey_oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_intkey_oauth_provider_user"),
    )
    id: UUID = Field(default_factory=uuid7, primary_key=True)
    provider: str = Field(max_length=50)
    provider_user_id: str = Field(max_length=320)
    user_id: int = Field(foreign_key="intkey_users.id", ondelete="CASCADE")
    provider_email: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntPasskey(SQLModel, table=True):
    __tablename__ = "intkey_passkeys"
    id: UUID = Field(default_factory=uuid7, primary_key=True)
    user_id: int = Field(foreign_key="intkey_users.id", ondelete="CASCADE", index=True)
    credential_id: str = Field(unique=True, index=True, max_length=512)
    public_key: str = ""
    sign_count: int = 0
    device_name: str = Field(default="", max_length=200)
    transports: str = ""
    backed_up: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime | None = None


class IntUserSchema(UserSchema[int]):
    roles: list[str] = Field(default_factory=list)


class StrUserSchema(UserSchema[str]):
    pass


async def _make_app(user_model, refresh_model, user_schema):
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=user_model,
        refresh_token_model=refresh_model,
        user_schema=user_schema,
        create_user_schema=CreateUserSchema,
    )
    fullauth = FullAuth(
        config=FullAuthConfig(SECRET_KEY=SECRET, PREVENT_REGISTRATION_ENUMERATION=False),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app)
    return app, adapter, fullauth, engine


# ── Full round trip per key type ────────────────────────────────────


@pytest.mark.parametrize(
    ("user_model", "refresh_model", "schema", "id_type"),
    [
        (IntUser, IntRefreshToken, IntUserSchema, int),
        (StrUser, StrRefreshToken, StrUserSchema, str),
    ],
    ids=["int-key", "str-key"],
)
@pytest.mark.asyncio
async def test_full_auth_round_trip_for_key_type(user_model, refresh_model, schema, id_type):
    """Register, login, /me, and refresh rotation all work on a non-UUID key."""
    app, adapter, _, engine = await _make_app(user_model, refresh_model, schema)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "k@test.com", "password": "securepass123"},
        )
        assert r.status_code == 201, r.text
        assert isinstance(r.json()["id"], id_type)
        registered_id = r.json()["id"]

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "k@test.com", "password": "securepass123"},
        )
        assert r.status_code == 200, r.text
        tokens = r.json()

        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["id"] == registered_id

        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert r.status_code == 200, r.text
        rotated = r.json()

        # The rotated access token still resolves to the same user.
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {rotated['access_token']}"},
        )
        assert r.status_code == 200
        assert r.json()["id"] == registered_id

        # Reusing the old refresh token burns the family (reuse detection works
        # the same regardless of key type).
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert r.status_code == 401

        r = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {rotated['access_token']}"},
        )
        assert r.status_code == 204

    await engine.dispose()


@pytest.mark.asyncio
async def test_integer_keys_are_sequential():
    """Integer keys come from the database sequence, so they increment."""
    app, adapter, _, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ids = []
        for i in range(3):
            r = await client.post(
                "/api/v1/auth/register",
                json={"email": f"seq{i}@test.com", "password": "securepass123"},
            )
            assert r.status_code == 201, r.text
            ids.append(r.json()["id"])
    assert ids == sorted(ids) and len(set(ids)) == 3
    await engine.dispose()


# ── parse_user_id ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_parse_user_id_returns_declared_type():
    app, adapter, _, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    parsed = adapter.parse_user_id("42")
    assert parsed == 42 and isinstance(parsed, int)
    await engine.dispose()


@pytest.mark.asyncio
async def test_parse_user_id_defaults_to_uuid_for_unparameterized_schema(adapter):
    """A schema that does not parameterise UserSchema keeps UUID behaviour."""
    from uuid import UUID, uuid4

    raw = str(uuid4())
    assert adapter.parse_user_id(raw) == UUID(raw)
    with pytest.raises((ValueError, ValidationError)):
        adapter.parse_user_id("not-a-uuid")


@pytest.mark.asyncio
async def test_parse_user_id_rejects_malformed_subject():
    app, adapter, _, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    for bad in ["abc", "", "1.5", "  "]:
        with pytest.raises((ValueError, ValidationError)):
            adapter.parse_user_id(bad)
    await engine.dispose()


# ── Malformed subjects return 401, never 500 ────────────────────────


@pytest.mark.asyncio
async def test_malformed_subject_is_401_on_protected_route():
    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    token = fullauth.token_engine.create_access_token(user_id="not-an-int")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
    await engine.dispose()


@pytest.mark.asyncio
async def test_malformed_subject_is_401_on_refresh():
    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    meta = fullauth.token_engine.create_refresh_token(user_id="not-an-int")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": meta.token})
        assert r.status_code == 401
    await engine.dispose()


@pytest.mark.asyncio
async def test_malformed_subject_is_rejected_by_email_verify_and_reset():
    """Both purpose-scoped flows convert the subject; neither may raise a 500."""
    from fastapi_fullauth.exceptions import TokenError
    from fastapi_fullauth.flows.email_verify import verify_email
    from fastapi_fullauth.flows.password_reset import reset_password

    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    engine_ = fullauth.token_engine

    verify_token = engine_.create_access_token(
        user_id="not-an-int", extra={"purpose": "email_verify"}
    )
    with pytest.raises(TokenError):
        await verify_email(adapter, engine_, verify_token)

    reset_token = engine_.create_access_token(
        user_id="not-an-int", extra={"purpose": "password_reset"}
    )
    with pytest.raises(TokenError):
        await reset_password(adapter, engine_, reset_token, "newsecurepass123")

    await engine.dispose()


@pytest.mark.asyncio
async def test_logout_tolerates_malformed_subject():
    """The after_logout hook converts the subject; a bad one must not 500."""
    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    token = fullauth.token_engine.create_access_token(user_id="not-an-int")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 204
    await engine.dispose()


# ── The full adapter contract on integer keys ───────────────────────


class TestIntKeyAdapterConformance(AdapterConformance):
    """Every shared contract test, run against integer-keyed models.

    OAuth accounts, passkeys, sessions, transactions, and the HTTP round trips
    all execute here with int ids; role and permission tests skip because no
    role models are wired, which the suite handles via supports_feature.
    """

    @pytest.fixture
    async def db(self):
        engine = create_async_engine("sqlite+aiosqlite://", echo=False)

        # Same recipe as conftest.db: aiosqlite's lazy BEGIN breaks SAVEPOINT
        # and rollback semantics, which the transaction contract tests rely on.
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
    def adapter(self, db):
        return SQLModelAdapter(
            session_maker=db,
            user_model=IntUser,
            refresh_token_model=IntRefreshToken,
            oauth_account_model=IntOAuthAccount,
            passkey_model=IntPasskey,
            user_schema=IntUserSchema,
        )


# ── Verification and reset flows on integer keys ────────────────────


@pytest.mark.asyncio
async def test_email_verify_round_trip_with_int_keys():
    from fastapi_fullauth.flows.email_verify import create_email_verification_token, verify_email

    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    user = await adapter.create_user(
        CreateUserSchema(email="v@test.com", password="securepass123"), hashed_password=None
    )
    assert user.is_verified is False

    token = await create_email_verification_token(adapter, fullauth.token_engine, user.id)
    assert token is not None
    verified = await verify_email(adapter, fullauth.token_engine, token)
    assert verified is not None and verified.is_verified is True
    await engine.dispose()


@pytest.mark.asyncio
async def test_password_reset_round_trip_with_int_keys():
    from fastapi_fullauth.core.crypto import hash_password, verify_password
    from fastapi_fullauth.flows.password_reset import request_password_reset, reset_password

    app, adapter, fullauth, engine = await _make_app(IntUser, IntRefreshToken, IntUserSchema)
    await adapter.create_user(
        CreateUserSchema(email="r@test.com", password="oldpass12345"),
        hashed_password=hash_password("oldpass12345"),
    )

    token = await request_password_reset(adapter, fullauth.token_engine, "r@test.com")
    assert token is not None
    user = await reset_password(adapter, fullauth.token_engine, token, "newpass12345")
    assert user is not None
    assert verify_password("newpass12345", await adapter.get_hashed_password(user.id))
    await engine.dispose()


# ── Schema/model mismatch guard ─────────────────────────────────────


def test_mismatched_id_types_raise_at_construction():
    """An int schema over a UUID table must fail loudly, not 401 silently."""
    from tests.conftest import RefreshToken, User

    with pytest.raises(ValueError, match="User id type mismatch") as exc:
        SQLModelAdapter(
            session_maker=None,  # type: ignore[arg-type]
            user_model=User,
            refresh_token_model=RefreshToken,
            user_schema=IntUserSchema,
        )
    message = str(exc.value)
    assert "int" in message and "UUID" in message


def test_matching_id_types_construct_cleanly():
    """Every valid pairing must construct, so the guard cannot false-alarm."""
    from tests.conftest import RefreshToken, User

    SQLModelAdapter(
        session_maker=None,  # type: ignore[arg-type]
        user_model=User,
        refresh_token_model=RefreshToken,
    )
    SQLModelAdapter(
        session_maker=None,  # type: ignore[arg-type]
        user_model=IntUser,
        refresh_token_model=IntRefreshToken,
        user_schema=IntUserSchema,
    )
    SQLModelAdapter(
        session_maker=None,  # type: ignore[arg-type]
        user_model=StrUser,
        refresh_token_model=StrRefreshToken,
        user_schema=StrUserSchema,
    )


def test_every_adapter_reports_its_model_key_type():
    """Each ORM needs its own introspection, so prove all of them work."""
    from uuid import UUID

    from tests.conftest import RefreshToken, User

    sql = SQLModelAdapter(
        session_maker=None,  # type: ignore[arg-type]
        user_model=User,
        refresh_token_model=RefreshToken,
    )
    assert sql.model_user_id_type() is UUID

    from fastapi_fullauth.adapters.tortoise import TortoiseAdapter
    from fastapi_fullauth.models.tortoise import (
        RefreshTokenMixin as TortoiseRefresh,
    )
    from fastapi_fullauth.models.tortoise import (
        UserMixin as TortoiseUser,
    )

    tortoise = TortoiseAdapter(user_model=TortoiseUser, refresh_token_model=TortoiseRefresh)
    assert tortoise.model_user_id_type() is UUID

    from fastapi_fullauth.adapters.beanie import BeanieAdapter
    from fastapi_fullauth.models.beanie import RefreshTokenDocument, UserDocument

    beanie = BeanieAdapter(user_model=UserDocument, refresh_token_model=RefreshTokenDocument)
    assert beanie.model_user_id_type() is UUID


def test_mismatch_is_detected_on_tortoise_and_beanie():
    """The guard is not SQL-only; every adapter fails fast on a mismatch."""
    from fastapi_fullauth.adapters.beanie import BeanieAdapter
    from fastapi_fullauth.adapters.tortoise import TortoiseAdapter
    from fastapi_fullauth.models.beanie import RefreshTokenDocument, UserDocument
    from fastapi_fullauth.models.tortoise import (
        RefreshTokenMixin as TortoiseRefresh,
    )
    from fastapi_fullauth.models.tortoise import (
        UserMixin as TortoiseUser,
    )

    with pytest.raises(ValueError, match="User id type mismatch"):
        TortoiseAdapter(
            user_model=TortoiseUser,
            refresh_token_model=TortoiseRefresh,
            user_schema=IntUserSchema,
        )

    with pytest.raises(ValueError, match="User id type mismatch"):
        BeanieAdapter(
            user_model=UserDocument,
            refresh_token_model=RefreshTokenDocument,
            user_schema=IntUserSchema,
        )


def test_unparameterized_schema_matches_uuid_model():
    """The default schema over the default UUID model stays valid."""
    from tests.conftest import RefreshToken, User

    adapter = SQLModelAdapter(
        session_maker=None,  # type: ignore[arg-type]
        user_model=User,
        refresh_token_model=RefreshToken,
    )
    from uuid import UUID

    assert adapter.user_id_annotation() is UUID


# ── Schema behaviour ────────────────────────────────────────────────


def test_user_schema_parameterization():
    from uuid import UUID, uuid4

    class Plain(UserSchema):
        pass

    assert isinstance(Plain(id=uuid4(), email="a@b.com").id, UUID)
    assert isinstance(IntUserSchema(id=5, email="a@b.com").id, int)
    assert isinstance(StrUserSchema(id="abc", email="a@b.com").id, str)

    with pytest.raises(ValidationError):
        Plain(id="not-a-uuid", email="a@b.com")


def test_refresh_token_dto_accepts_every_key_type():
    from uuid import uuid4

    from fastapi_fullauth.types import RefreshToken as RefreshTokenDTO

    expires = datetime.now(timezone.utc) + timedelta(days=1)
    for value in (uuid4(), 7, "abc"):
        dto = RefreshTokenDTO(token="t", user_id=value, expires_at=expires, family_id="f")
        assert dto.user_id == value
