from __future__ import annotations

import pytest

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.tokens import InMemoryBlacklist, TokenEngine
from fastapi_fullauth.exceptions import TokenBlacklistedError


@pytest.fixture
def engine():
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    return TokenEngine(config=config, blacklist=InMemoryBlacklist())


def test_create_and_decode_access_token(engine):
    token = engine.create_access_token("user-123", roles=["admin"])
    payload = engine.decode_token(token)
    assert payload.sub == "user-123"
    assert payload.type == "access"
    assert "admin" in payload.roles


def test_create_and_decode_refresh_token(engine):
    token = engine.create_refresh_token("user-123")
    payload = engine.decode_token(token)
    assert payload.sub == "user-123"
    assert payload.type == "refresh"


def test_token_pair(engine):
    access, refresh = engine.create_token_pair("user-123", roles=["editor"])
    a_payload = engine.decode_token(access)
    r_payload = engine.decode_token(refresh)
    assert a_payload.type == "access"
    assert r_payload.type == "refresh"
    assert a_payload.sub == r_payload.sub == "user-123"


def test_blacklist_token(engine):
    token = engine.create_access_token("user-123")
    payload = engine.decode_token(token)
    engine.blacklist_token(payload.jti)

    with pytest.raises(TokenBlacklistedError):
        engine.decode_token(token)


def test_extra_claims(engine):
    token = engine.create_access_token("user-123", extra={"purpose": "email_verify"})
    payload = engine.decode_token(token)
    assert payload.extra["purpose"] == "email_verify"


def test_invalid_token(engine):
    from fastapi_fullauth.exceptions import TokenError

    with pytest.raises(TokenError):
        engine.decode_token("garbage.token.here")
