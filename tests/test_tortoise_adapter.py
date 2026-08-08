"""Integration tests for TortoiseAdapter with a real in-memory SQLite database.

Self-contained: the shared conftest harness is SQLModel-based, so this module
defines its own concrete Tortoise models and DB lifecycle and overrides the
conftest ``adapter`` fixture; the shared contract runs via the
AdapterConformance subclass below.
"""

from datetime import datetime, timezone

import pytest
from pydantic import Field
from tortoise import Tortoise, fields

from fastapi_fullauth import UserSchema
from fastapi_fullauth.adapters.tortoise import TortoiseAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.models.tortoise import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
)
from fastapi_fullauth.types import CreateUserSchema, RefreshToken
from tests.adapter_conformance import AdapterConformance

# --- Concrete models (app label "models" -> this module) ---------------


class Role(RoleMixin):
    permissions = fields.ManyToManyField(
        "models.Permission", related_name="roles", through="fullauth_role_permissions"
    )

    class Meta:
        table = "fullauth_roles"


class Permission(PermissionMixin):
    class Meta:
        table = "fullauth_permissions"


class RefreshTokenModel(RefreshTokenMixin):
    class Meta:
        table = "fullauth_refresh_tokens"


class OAuthAccountModel(OAuthAccountMixin):
    class Meta:
        table = "fullauth_oauth_accounts"
        unique_together = (("provider", "provider_user_id"),)


class Passkey(PasskeyMixin):
    class Meta:
        table = "fullauth_passkeys"


class User(UserMixin):
    display_name = fields.CharField(max_length=100, default="")
    roles = fields.ManyToManyField(
        "models.Role", related_name="users", through="fullauth_user_roles"
    )

    class Meta:
        table = "fullauth_users"


class UserSchemaWithRoles(UserSchema):
    roles: list[str] = Field(default_factory=list)


# --- Fixtures ----------------------------------------------------------


@pytest.fixture
async def tortoise_db():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": [__name__]})
    await Tortoise.generate_schemas()
    try:
        yield
    finally:
        await Tortoise.close_connections()


@pytest.fixture
def adapter(tortoise_db):
    return TortoiseAdapter(
        user_model=User,
        refresh_token_model=RefreshTokenModel,
        role_model=Role,
        permission_model=Permission,
        oauth_account_model=OAuthAccountModel,
        passkey_model=Passkey,
        user_schema=UserSchemaWithRoles,
    )


# --- Shared conformance suite ------------------------------------------


class TestTortoiseAdapterConformance(AdapterConformance):
    pass


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
    # FK cascade removes the refresh token; M2M cascade removes the role link
    assert await adapter.get_refresh_token("del-tok") is None


# --- supports_feature / missing-model guards ---------------------------


@pytest.mark.asyncio
async def test_core_only_adapter_reports_capabilities(tortoise_db):
    core = TortoiseAdapter(user_model=User, refresh_token_model=RefreshTokenModel)
    assert core.supports_feature("session") is True
    assert core.supports_feature("role") is False
    assert core.supports_feature("oauth") is False
    user = await core.create_user(
        CreateUserSchema(email="core@test.com", password="p"),
        hashed_password=hash_password("p"),
    )
    assert await core.get_user_roles(user.id) == []


@pytest.mark.asyncio
async def test_missing_model_raises_naming_kwarg(tortoise_db):
    core = TortoiseAdapter(user_model=User, refresh_token_model=RefreshTokenModel)
    with pytest.raises(RuntimeError, match="oauth_account_model"):
        await core.get_oauth_account("google", "x")
    with pytest.raises(RuntimeError, match="passkey_model"):
        await core.get_passkey_by_credential_id("x")


def test_permission_requires_role_model(tortoise_db):
    with pytest.raises(ValueError, match="role_model"):
        TortoiseAdapter(
            user_model=User,
            refresh_token_model=RefreshTokenModel,
            permission_model=Permission,
        )
