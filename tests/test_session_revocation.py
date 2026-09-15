"""Ending a session must also invalidate the access tokens it already issued.

Revoking refresh tokens in storage only stops a session from minting new
tokens; access tokens issued before that stay valid until they expire. Each
test below issues an access token, ends its session one way, and asserts the
token is rejected immediately.
"""

import pytest

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.blacklist import InMemoryTokenBlacklist, TokenBlacklist
from fastapi_fullauth.core.tokens import TokenEngine

SECRET = "test-secret-key-that-is-long-enough-32b"
PASSWORD = "securepass123"


async def _register(client, email):
    r = await client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD})
    assert r.status_code == 201, r.text


async def _login(client, email="user@test.com", password=PASSWORD):
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _me_status(client, tokens):
    return (await client.get("/api/v1/auth/me", headers=_auth(tokens))).status_code


@pytest.mark.asyncio
async def test_logout_invalidates_earlier_access_tokens_of_the_same_session(
    client, registered_user
):
    first = await _login(client)
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    rotated = r.json()

    r = await client.post("/api/v1/auth/logout", headers=_auth(rotated))
    assert r.status_code == 204

    # Issued before the rotation, never presented at logout, same session.
    assert await _me_status(client, first) == 401


@pytest.mark.asyncio
async def test_revoking_a_session_invalidates_its_access_tokens(client, registered_user):
    laptop = await _login(client)
    phone = await _login(client)

    sessions = (await client.get("/api/v1/auth/sessions", headers=_auth(laptop))).json()
    phone_family = next(s["family_id"] for s in sessions if not s["current"])

    r = await client.delete(f"/api/v1/auth/sessions/{phone_family}", headers=_auth(laptop))
    assert r.status_code == 204

    assert await _me_status(client, phone) == 401
    assert await _me_status(client, laptop) == 200


@pytest.mark.asyncio
async def test_revoke_other_sessions_invalidates_their_access_tokens(client, registered_user):
    laptop = await _login(client)
    phone = await _login(client)
    await _register(client, "other@test.com")
    other_user = await _login(client, "other@test.com")

    r = await client.post("/api/v1/auth/sessions/revoke-others", headers=_auth(laptop))
    assert r.status_code == 200

    assert await _me_status(client, phone) == 401
    assert await _me_status(client, laptop) == 200
    assert await _me_status(client, other_user) == 200


@pytest.mark.asyncio
async def test_password_change_invalidates_access_tokens_of_every_session(client, registered_user):
    laptop = await _login(client)
    phone = await _login(client)

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "brandnewpass456"},
        headers=_auth(laptop),
    )
    assert r.status_code == 200

    assert await _me_status(client, phone) == 401
    assert await _me_status(client, laptop) == 401


@pytest.mark.asyncio
async def test_password_reset_invalidates_existing_access_tokens(client, fullauth, registered_user):
    sent = []

    @fullauth.hooks.on("send_password_reset_email")
    async def capture(email, token):
        sent.append(token)

    session = await _login(client)
    await client.post("/api/v1/auth/password-reset/request", json={"email": "user@test.com"})
    r = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": sent[0], "new_password": "brandnewpass456"},
    )
    assert r.status_code == 200

    assert await _me_status(client, session) == 401


@pytest.mark.asyncio
async def test_refresh_token_reuse_invalidates_access_tokens_of_the_family(client, registered_user):
    first = await _login(client)
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    rotated = r.json()
    assert await _me_status(client, rotated) == 200

    # Replaying the already-rotated refresh token signals theft of the family.
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 401

    assert await _me_status(client, rotated) == 401


@pytest.mark.asyncio
async def test_revoke_family_is_a_no_op_when_the_blacklist_is_disabled():
    blacklist = InMemoryTokenBlacklist()
    engine = TokenEngine(
        FullAuthConfig(SECRET_KEY=SECRET, BLACKLIST_ENABLED=False), blacklist=blacklist
    )
    await engine.revoke_family("family-1")
    assert blacklist._blacklisted == {}


@pytest.mark.asyncio
async def test_custom_blacklist_backend_without_is_any_blacklisted_still_revokes_families():
    """Backends written before is_any_blacklisted existed implement only
    add/is_blacklisted; the default must check the family through them."""

    class LegacyBlacklist(TokenBlacklist):
        def __init__(self):
            self.keys = set()

        async def add(self, jti, ttl_seconds=None):
            self.keys.add(jti)

        async def is_blacklisted(self, jti):
            return jti in self.keys

    engine = TokenEngine(FullAuthConfig(SECRET_KEY=SECRET), blacklist=LegacyBlacklist())
    access, _ = engine.create_token_pair(user_id="u1")
    await engine.decode_token(access)

    payload = await engine.decode_token(access)
    await engine.revoke_family(payload.family_id)

    from fastapi_fullauth.exceptions import TokenBlacklistedError

    with pytest.raises(TokenBlacklistedError):
        await engine.decode_token(access)


@pytest.mark.asyncio
async def test_redis_blacklist_checks_token_and_family_in_one_call():
    import fakeredis.aioredis

    from fastapi_fullauth.core.blacklist import RedisTokenBlacklist

    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    calls = []
    original_exists = fake.exists

    async def counting_exists(*keys):
        calls.append(keys)
        return await original_exists(*keys)

    fake.exists = counting_exists

    bl = RedisTokenBlacklist.__new__(RedisTokenBlacklist)
    bl._redis = fake
    bl._default_ttl = 300
    bl._prefix = "fullauth:blacklist:"

    assert await bl.is_any_blacklisted("jti-1", "family:f1") is False
    await bl.add("family:f1", 60)
    assert await bl.is_any_blacklisted("jti-1", "family:f1") is True
    assert await bl.is_any_blacklisted("jti-2", "family:f2") is False
    assert all(len(keys) == 2 for keys in calls) and len(calls) == 3
