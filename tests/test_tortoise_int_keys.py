"""TortoiseAdapter on integer user keys, using the bundled mixins.

Kept in its own module because Tortoise registers every model in the module it
is initialised with. Only the user primary key is overridden: Tortoise derives a
foreign key's column type from the model it points at, so the related mixins
need no change.

Table names differ from test_tortoise_adapter because Tortoise caches query
executors per process by model and table name; a second ``User`` on
``fullauth_users`` would reuse the other module's column list.
"""

from datetime import datetime, timedelta, timezone

import pytest
from tortoise import Tortoise, fields

from fastapi_fullauth.adapters.tortoise import TortoiseAdapter
from fastapi_fullauth.models.tortoise import RefreshTokenMixin, UserMixin
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserSchema


class User(UserMixin):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "intkey_users"


class RefreshTokenModel(RefreshTokenMixin):
    class Meta:
        table = "intkey_refresh_tokens"


class IntUserSchema(UserSchema[int]):
    pass


@pytest.fixture
async def adapter():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": [__name__]})
    await Tortoise.generate_schemas()
    try:
        yield TortoiseAdapter(
            user_model=User,
            refresh_token_model=RefreshTokenModel,
            user_schema=IntUserSchema,
        )
    finally:
        await Tortoise.close_connections()


@pytest.mark.asyncio
async def test_integer_keys_round_trip_through_related_tables(adapter):
    user = await adapter.create_user(
        CreateUserSchema(email="t@test.com", password="securepass123"), hashed_password="x"
    )
    assert isinstance(user.id, int)
    assert await adapter.get_user_by_id(adapter.parse_user_id(str(user.id))) == user

    await adapter.store_refresh_token(
        RefreshToken(
            token="digest",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            family_id="family",
        )
    )
    stored = await adapter.get_refresh_token("digest")
    assert stored is not None and stored.user_id == user.id
    assert [s.family_id for s in await adapter.list_user_sessions(user.id)] == ["family"]
