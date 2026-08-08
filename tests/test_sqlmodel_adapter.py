"""Integration tests for SQLModelAdapter with a real SQLite database.

The `db` and `adapter` fixtures come from tests/conftest.py; the shared
contract runs via the AdapterConformance subclass below.
"""

from tests.adapter_conformance import AdapterConformance


class TestSQLModelAdapterConformance(AdapterConformance):
    pass


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
