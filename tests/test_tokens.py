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


@pytest.mark.asyncio
async def test_inmemory_blacklist_zero_ttl_is_bounded_not_forever():
    """A ttl of 0 means 'already expired', not 'no expiry'. It must store a
    finite entry (so the dict can't grow without bound), while an explicit
    None still means no-expiry."""
    bl = InMemoryTokenBlacklist()

    await bl.add("jti-zero", ttl_seconds=0)
    assert bl._blacklisted["jti-zero"] is not None  # bounded, self-expiring

    await bl.add("jti-none", ttl_seconds=None)
    assert bl._blacklisted["jti-none"] is None  # explicit no-expiry preserved


@pytest.mark.asyncio
async def test_redis_blacklist_zero_ttl_does_not_become_default():
    """setex(0) would raise and the old `ttl_seconds or default` silently swapped
    a 0 for the 1800s default. A 0 must floor to a finite 1s entry instead."""
    import fakeredis.aioredis

    from fastapi_fullauth.core.blacklist import RedisTokenBlacklist

    bl = RedisTokenBlacklist.__new__(RedisTokenBlacklist)
    bl._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    bl._default_ttl = 1800
    bl._prefix = "fullauth:blacklist:"

    await bl.add("jti-zero", ttl_seconds=0)
    # Assert in milliseconds: `ttl` (whole seconds) floors a just-set 1s key to 0,
    # which is flaky. `pttl` right after setex is ~1000ms and unambiguously not the
    # 1800s (1_800_000 ms) default.
    pttl = await bl._redis.pttl("fullauth:blacklist:jti-zero")
    assert 0 < pttl <= 1000  # floored to ~1s, not the 1800s default


@pytest.mark.asyncio
async def test_decode_token_tolerates_non_dict_extra(engine):
    """A signed token whose `extra` claim isn't a dict must decode to extra={}
    rather than raising AttributeError (which would escape as a 500)."""
    from datetime import datetime, timedelta, timezone

    import jwt

    now = datetime.now(timezone.utc)
    raw = jwt.encode(
        {
            "sub": "user-123",
            "exp": now + timedelta(minutes=5),
            "iat": now,
            "jti": "non-dict-extra",
            "type": "access",
            "extra": "not-a-dict",
        },
        engine.config.SECRET_KEY,
        algorithm=engine.config.ALGORITHM,
    )

    payload = await engine.decode_token(raw)
    assert payload.extra == {}
