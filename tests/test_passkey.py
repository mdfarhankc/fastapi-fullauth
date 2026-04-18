"""Tests for passkey (WebAuthn) challenge store and adapter methods."""

from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from uuid_utils import uuid7

from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.passkey import PasskeyRecord  # noqa: F401
from fastapi_fullauth.core.challenges import InMemoryChallengeStore
from fastapi_fullauth.types import PasskeyCredential
from tests.conftest import User, UserSchemaWithRoles

# ── Challenge store tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_challenge_store_and_pop():
    store = InMemoryChallengeStore()
    await store.store("key1", "challenge123", ttl=60)

    result = await store.pop("key1")
    assert result == "challenge123"

    # second pop returns None (single-use)
    result = await store.pop("key1")
    assert result is None


@pytest.mark.asyncio
async def test_challenge_store_expired():
    store = InMemoryChallengeStore()
    await store.store("key1", "challenge123", ttl=0)

    # expired immediately
    result = await store.pop("key1")
    assert result is None


@pytest.mark.asyncio
async def test_challenge_store_missing_key():
    store = InMemoryChallengeStore()
    result = await store.pop("nonexistent")
    assert result is None


# ── Passkey adapter tests ──────────────────────────────────────────


@pytest.fixture
async def passkey_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def passkey_adapter(passkey_db):
    return SQLModelAdapter(
        session_maker=passkey_db, user_model=User, user_schema=UserSchemaWithRoles
    )


@pytest.mark.asyncio
async def test_passkey_crud(passkey_adapter):
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema

    # create user
    data = CreateUserSchema(email="passkey@test.com", password="securepass123")
    user = await passkey_adapter.create_user(data, hashed_password=hash_password("securepass123"))

    # store passkey
    pk = PasskeyCredential(
        id=UUID(str(uuid7())),
        user_id=user.id,
        credential_id="cred-abc-123",
        public_key="pubkey-xyz",
        sign_count=0,
        device_name="Test Device",
        transports=["internal"],
        backed_up=False,
    )
    stored = await passkey_adapter.store_passkey(pk)
    assert stored.credential_id == "cred-abc-123"

    # get by credential_id
    fetched = await passkey_adapter.get_passkey_by_credential_id("cred-abc-123")
    assert fetched is not None
    assert fetched.device_name == "Test Device"
    assert fetched.transports == ["internal"]

    # list user passkeys
    passkeys = await passkey_adapter.get_user_passkeys(user.id)
    assert len(passkeys) == 1

    # update sign count
    await passkey_adapter.update_passkey_sign_count("cred-abc-123", 5)
    updated = await passkey_adapter.get_passkey_by_credential_id("cred-abc-123")
    assert updated is not None
    assert updated.sign_count == 5
    assert updated.last_used_at is not None

    # delete
    await passkey_adapter.delete_passkey(pk.id)
    assert await passkey_adapter.get_passkey_by_credential_id("cred-abc-123") is None


@pytest.mark.asyncio
async def test_passkey_not_found(passkey_adapter):
    result = await passkey_adapter.get_passkey_by_credential_id("nonexistent")
    assert result is None
