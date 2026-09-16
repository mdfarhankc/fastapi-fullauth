"""Tests for passkey (WebAuthn) challenge store and adapter methods."""

from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from uuid_utils import uuid7

from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.protection.challenges import InMemoryChallengeStore
from fastapi_fullauth.types import PasskeyCredential
from tests.conftest import Passkey, RefreshToken, User, UserSchemaWithRoles

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
        session_maker=passkey_db,
        user_model=User,
        refresh_token_model=RefreshToken,
        passkey_model=Passkey,
        user_schema=UserSchemaWithRoles,
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


@pytest.mark.asyncio
async def test_passkey_sign_count_compare_and_swap(passkey_adapter):
    """Sign count update is a CAS: only advances on strictly greater values."""
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema

    data = CreateUserSchema(email="cas@test.com", password="securepass123")
    user = await passkey_adapter.create_user(data, hashed_password=hash_password("securepass123"))
    pk = PasskeyCredential(
        id=UUID(str(uuid7())),
        user_id=user.id,
        credential_id="cred-cas",
        public_key="pubkey",
        sign_count=5,
        device_name="Key",
        transports=[],
        backed_up=False,
    )
    await passkey_adapter.store_passkey(pk)

    # strictly greater -> advances
    assert await passkey_adapter.update_passkey_sign_count("cred-cas", 6) is True
    assert (await passkey_adapter.get_passkey_by_credential_id("cred-cas")).sign_count == 6

    # equal -> rejected (clone/race signal); counter unchanged
    assert await passkey_adapter.update_passkey_sign_count("cred-cas", 6) is False
    assert (await passkey_adapter.get_passkey_by_credential_id("cred-cas")).sign_count == 6

    # lower -> rejected; counter unchanged
    assert await passkey_adapter.update_passkey_sign_count("cred-cas", 3) is False
    assert (await passkey_adapter.get_passkey_by_credential_id("cred-cas")).sign_count == 6


@pytest.mark.asyncio
async def test_passkey_sign_count_zero_counter(passkey_adapter):
    """Authenticators that never maintain a counter (sign_count stays 0) return False
    from the CAS but the row still exists and last_used_at is updated."""
    from fastapi_fullauth.core.crypto import hash_password
    from fastapi_fullauth.types import CreateUserSchema

    data = CreateUserSchema(email="zero@test.com", password="securepass123")
    user = await passkey_adapter.create_user(data, hashed_password=hash_password("securepass123"))
    pk = PasskeyCredential(
        id=UUID(str(uuid7())),
        user_id=user.id,
        credential_id="cred-zero",
        public_key="pubkey",
        sign_count=0,
        device_name="Synced passkey",
        transports=[],
        backed_up=True,
    )
    await passkey_adapter.store_passkey(pk)

    # 0 is not strictly greater than 0 -> False, but last_used_at bumped
    result = await passkey_adapter.update_passkey_sign_count("cred-zero", 0)
    assert result is False
    stored = await passkey_adapter.get_passkey_by_credential_id("cred-zero")
    assert stored is not None
    assert stored.sign_count == 0
    assert stored.last_used_at is not None


# ── Transports ─────────────────────────────────────────────────────


async def _passkey_user(adapter):
    from fastapi_fullauth.types import CreateUserSchema

    return await adapter.create_user(
        CreateUserSchema(email="pk@test.com", password="securepass123"), hashed_password="x"
    )


@pytest.mark.asyncio
async def test_authentication_options_skip_unknown_stored_transports(passkey_adapter):
    """Transports are client-supplied; one unrecognised value stored for a
    credential must not break passkey sign-in for the whole account."""
    from fastapi_fullauth.flows.passkey import begin_authentication

    user = await _passkey_user(passkey_adapter)
    await passkey_adapter.store_passkey(
        PasskeyCredential(
            id=UUID(str(uuid7())),
            user_id=user.id,
            credential_id="Y3JlZC0x",
            public_key="cGs",
            transports=["usb", "made-up-transport"],
        )
    )

    options = await begin_authentication(
        rp_id="example.com",
        challenge_store=InMemoryChallengeStore(),
        adapter=passkey_adapter,
        user_id=user.id,
        email_provided=True,
    )
    assert options["allowCredentials"][0]["transports"] == ["usb"]


@pytest.mark.asyncio
async def test_registration_stores_only_known_transports(passkey_adapter):
    from types import SimpleNamespace
    from unittest.mock import patch

    from fastapi_fullauth.flows.passkey import complete_registration

    user = await _passkey_user(passkey_adapter)
    store = InMemoryChallengeStore()
    await store.store("passkey:reg:k", "Y2hhbGxlbmdl", ttl=60)
    verification = SimpleNamespace(
        credential_id=b"cred-2",
        credential_public_key=b"pk",
        sign_count=0,
        credential_backed_up=False,
    )
    credential = {
        "id": "Y3JlZC0y",
        "response": {"transports": ["internal", "hybrid", "bogus", 42, None]},
    }

    with patch("webauthn.verify_registration_response", return_value=verification):
        passkey = await complete_registration(
            challenge_key="passkey:reg:k",
            credential=credential,
            device_name="Laptop",
            user=user,
            rp_id="example.com",
            expected_origin="https://example.com",
            challenge_store=store,
            adapter=passkey_adapter,
        )

    assert passkey.transports == ["internal", "hybrid"]
    stored = await passkey_adapter.get_passkey_by_credential_id(passkey.credential_id)
    assert stored is not None and stored.transports == ["internal", "hybrid"]
