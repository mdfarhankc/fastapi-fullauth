import pytest

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.blacklist import InMemoryTokenBlacklist
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import TokenBlacklistedError


@pytest.fixture
def engine():
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    return TokenEngine(config=config, blacklist=InMemoryTokenBlacklist())


@pytest.mark.asyncio
async def test_create_and_decode_access_token(engine):
    token = engine.create_access_token("user-123", roles=["admin"])
    payload = await engine.decode_token(token)
    assert payload.sub == "user-123"
    assert payload.type == "access"
    assert "admin" in payload.roles


@pytest.mark.asyncio
async def test_create_and_decode_refresh_token(engine):
    meta = engine.create_refresh_token("user-123")
    assert meta.expires_at is not None
    assert meta.family_id is not None
    payload = await engine.decode_token(meta.token)
    assert payload.sub == "user-123"
    assert payload.type == "refresh"
    assert payload.family_id == meta.family_id


@pytest.mark.asyncio
async def test_token_pair(engine):
    access, refresh_meta = engine.create_token_pair("user-123", roles=["editor"])
    a_payload = await engine.decode_token(access)
    r_payload = await engine.decode_token(refresh_meta.token)
    assert a_payload.type == "access"
    assert r_payload.type == "refresh"
    assert a_payload.sub == r_payload.sub == "user-123"


@pytest.mark.asyncio
async def test_blacklist_token(engine):
    token = engine.create_access_token("user-123")
    payload = await engine.decode_token(token)
    await engine.blacklist_token(payload.jti)

    with pytest.raises(TokenBlacklistedError):
        await engine.decode_token(token)


@pytest.mark.asyncio
async def test_extra_claims(engine):
    token = engine.create_access_token("user-123", extra={"purpose": "email_verify"})
    payload = await engine.decode_token(token)
    assert payload.extra["purpose"] == "email_verify"


@pytest.mark.asyncio
async def test_invalid_token(engine):
    from fastapi_fullauth.exceptions import TokenError

    with pytest.raises(TokenError):
        await engine.decode_token("garbage.token.here")


@pytest.mark.asyncio
async def test_missing_required_claim_rejected(engine):
    from datetime import datetime, timedelta, timezone

    import jwt

    from fastapi_fullauth.exceptions import TokenError

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"exp": now + timedelta(minutes=5), "iat": now},  # no sub
        engine.config.SECRET_KEY,
        algorithm=engine.config.ALGORITHM,
    )
    with pytest.raises(TokenError):
        await engine.decode_token(token)


@pytest.mark.asyncio
async def test_decode_token_enforces_expected_type(engine):
    from fastapi_fullauth.exceptions import TokenError

    access = engine.create_access_token("user-123")
    refresh = engine.create_refresh_token("user-123").token

    # A refresh token must be rejected where an access token is required.
    with pytest.raises(TokenError):
        await engine.decode_token(refresh, expected_type="access")
    # ...and vice versa.
    with pytest.raises(TokenError):
        await engine.decode_token(access, expected_type="refresh")
    # Matching type still decodes.
    assert (await engine.decode_token(access, expected_type="access")).sub == "user-123"


@pytest.mark.asyncio
async def test_decode_token_enforces_expected_purpose(engine):
    from fastapi_fullauth.exceptions import TokenError

    reset = engine.create_access_token("user-123", extra={"purpose": "password_reset"})

    # Wrong purpose is rejected.
    with pytest.raises(TokenError):
        await engine.decode_token(reset, expected_purpose="email_verify")
    # A purpose-scoped token is rejected where no purpose is wanted is the
    # caller's job (current_user checks that); here, matching purpose decodes.
    assert (await engine.decode_token(reset, expected_purpose="password_reset")).sub == "user-123"


@pytest.mark.asyncio
async def test_blacklist_payload_bounds_ttl(engine):
    """blacklist_payload must store a finite expiry, never None (which would make
    the in-memory store grow without bound)."""
    token = engine.create_access_token("user-123")
    payload = await engine.decode_token(token)

    await engine.blacklist_payload(payload)

    stored = engine.blacklist._blacklisted[payload.jti]
    assert stored is not None  # bounded, self-expiring entry
    with pytest.raises(TokenBlacklistedError):
        await engine.decode_token(token)
