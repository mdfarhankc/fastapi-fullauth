"""Integration tests for BeanieAdapter against an in-process MongoDB (mongomock).

Self-contained: the shared conftest harness is SQLModel-based, so this module
defines its own Beanie documents and DB lifecycle and overrides the conftest
``adapter`` fixture; the shared contract runs via the AdapterConformance
subclass below.

No MongoDB server is required - ``mongomock-motor`` runs the whole suite in
process. Beanie asks the database for its collection names with driver kwargs
(``authorizedCollections`` / ``nameOnly``) that mongomock does not accept, so a
small shim strips them; everything the adapter relies on (single-document CAS,
unique indexes, ``$addToSet`` / ``$pull``, ``$lt`` conditional updates) is real
mongomock behaviour.
"""

from datetime import datetime, timezone

import mongomock
import pytest
from mongomock_motor import AsyncMongoMockClient
from pydantic import Field

from fastapi_fullauth import UserSchema
from fastapi_fullauth.adapters.beanie import BeanieAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.models.beanie import (
    OAuthAccountDocument,
    PasskeyDocument,
    PermissionDocument,
    RefreshTokenDocument,
    RoleDocument,
    UserDocument,
)
from fastapi_fullauth.types import CreateUserSchema, RefreshToken
from tests.adapter_conformance import AdapterConformance

# --- mongomock shim: drop driver-only kwargs Beanie passes on init -----

_orig_list_collection_names = mongomock.Database.list_collection_names


def _patched_list_collection_names(self, *args, **kwargs):
    kwargs.pop("authorizedCollections", None)
    kwargs.pop("nameOnly", None)
    return _orig_list_collection_names(self, *args, **kwargs)


mongomock.Database.list_collection_names = _patched_list_collection_names


# --- Concrete documents ------------------------------------------------


class User(UserDocument):
    display_name: str = ""


class RefreshTokenModel(RefreshTokenDocument):
    pass


class Role(RoleDocument):
    pass


class Permission(PermissionDocument):
    pass


class OAuthAccountModel(OAuthAccountDocument):
    pass


class Passkey(PasskeyDocument):
    pass


class UserSchemaWithRoles(UserSchema):
    roles: list[str] = Field(default_factory=list)


_DOCUMENTS = [User, RefreshTokenModel, Role, Permission, OAuthAccountModel, Passkey]


# --- Fixtures ----------------------------------------------------------


@pytest.fixture
async def beanie_db():
    from beanie import init_beanie

    client = AsyncMongoMockClient()
    await init_beanie(database=client["fullauth_test"], document_models=_DOCUMENTS)
    yield


@pytest.fixture
def adapter(beanie_db):
    return BeanieAdapter(
        user_model=User,
        refresh_token_model=RefreshTokenModel,
        role_model=Role,
        permission_model=Permission,
        oauth_account_model=OAuthAccountModel,
        passkey_model=Passkey,
        user_schema=UserSchemaWithRoles,
    )


# --- Shared conformance suite ------------------------------------------


class TestBeanieAdapterConformance(AdapterConformance):
    # MongoDB single-document CAS gives rotation its reuse-detection guarantee,
    # so the adapter keeps the inherited best-effort transaction (yields self,
    # no multi-document atomicity).
    atomic_transactions = False


# --- Adapter-specific tests --------------------------------------------


@pytest.mark.asyncio
async def test_delete_user_cascades(adapter):
    data = CreateUserSchema(email="del@test.com", password="pass123")
    user = await adapter.create_user(data, hashed_password=hash_password("pass123"))
    await adapter.assign_role(user.id, "editor")
    await adapter.store_refresh_token(
        RefreshToken(
            token="del-tok",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc),
            family_id="fam",
        )
    )

    await adapter.delete_user(user.id)
    assert await adapter.get_user_by_id(user.id) is None
    # MongoDB has no FK cascade; the adapter removes the refresh token explicitly
    assert await adapter.get_refresh_token("del-tok") is None


@pytest.mark.asyncio
async def test_transaction_is_best_effort_and_yields_self(adapter):
    # The best-effort transaction yields the adapter itself; the block still
    # runs every step (rollback semantics are covered by atomic_transactions).
    async with adapter.transaction() as tx:
        assert tx is adapter
        user = await tx.create_user(
            CreateUserSchema(email="tx-self@test.com", password="pass123"),
            hashed_password=hash_password("pass123"),
        )
        await tx.assign_role(user.id, "editor")

    fetched = await adapter.get_user_by_email("tx-self@test.com")
    assert fetched is not None
    assert "editor" in fetched.roles


# --- supports_feature / missing-model guards ---------------------------


@pytest.mark.asyncio
async def test_core_only_adapter_reports_capabilities(beanie_db):
    core = BeanieAdapter(user_model=User, refresh_token_model=RefreshTokenModel)
    assert core.supports_feature("session") is True
    assert core.supports_feature("role") is False
    assert core.supports_feature("oauth") is False
    user = await core.create_user(
        CreateUserSchema(email="core@test.com", password="p"),
        hashed_password=hash_password("p"),
    )
    assert await core.get_user_roles(user.id) == []


@pytest.mark.asyncio
async def test_missing_model_raises_naming_kwarg(beanie_db):
    core = BeanieAdapter(user_model=User, refresh_token_model=RefreshTokenModel)
    with pytest.raises(RuntimeError, match="oauth_account_model"):
        await core.get_oauth_account("google", "x")
    with pytest.raises(RuntimeError, match="passkey_model"):
        await core.get_passkey_by_credential_id("x")


def test_permission_requires_role_model():
    with pytest.raises(ValueError, match="role_model"):
        BeanieAdapter(
            user_model=User,
            refresh_token_model=RefreshTokenModel,
            permission_model=Permission,
        )
