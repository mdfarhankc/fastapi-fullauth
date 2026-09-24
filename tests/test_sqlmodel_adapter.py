"""Integration tests for SQLModelAdapter with a real SQLite database.

The `db` and `adapter` fixtures come from tests/conftest.py; the shared
contract runs via the AdapterConformance subclass below.
"""

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from tests.adapter_conformance import AdapterConformance
from tests.conftest import make_engine_and_sessionmaker


class TestSQLModelAdapterConformance(AdapterConformance):
    """Against SQLAlchemy's AsyncSession, which the docs offer first."""


class TestSQLModelAdapterWithSQLModelSession(AdapterConformance):
    """Against SQLModel's own AsyncSession, the other documented setup.

    It is not interchangeable with SQLAlchemy's: it overrides `execute()` and
    deprecates it. Running the whole contract here is what makes the
    deprecations-as-errors setting mean something for this adapter; without it
    that setting passes whether or not the adapter calls a deprecated API.
    """

    @pytest.fixture
    async def db(self):
        engine, session_maker = await make_engine_and_sessionmaker(AsyncSession)
        yield session_maker
        await engine.dispose()


# --- Schema parity with the SQLAlchemy mixins --------------------------


def test_sqlmodel_refresh_token_is_length_capped_varchar():
    """The refresh-token `token` is uniquely indexed, so it must be a bounded
    VARCHAR (not the AutoString 255 default, which truncates a refresh JWT on
    MySQL). Mirrors the SQLAlchemy mixin."""
    from tests.conftest import RefreshToken as RefreshTokenTable

    col = RefreshTokenTable.__table__.c.token
    # length 512 distinguishes it from both the AutoString 255 default and an
    # unbounded Text (length None); AutoString isn't a sqlalchemy.String subclass.
    assert col.type.length == 512
    assert col.unique is True
    assert col.index is True
