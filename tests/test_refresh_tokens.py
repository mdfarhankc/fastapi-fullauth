"""Tests for refresh token persistence, reuse detection, and Redis blacklist."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter


def _make_app(adapter=None, **fullauth_kwargs):
    """Helper to build a test app with given FullAuth config."""
    adapter = adapter or InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
        **fullauth_kwargs,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)
    return app, adapter, fullauth


# ---------------------------------------------------------------------------
# Login persists refresh token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_persists_refresh_token():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        refresh_token = r.json()["refresh_token"]

        # refresh token should be stored in adapter
        stored = await adapter.get_refresh_token(refresh_token)
        assert stored is not None
        assert stored.user_id is not None
        assert stored.family_id is not None
        assert stored.revoked is False


# ---------------------------------------------------------------------------
# Refresh persists new token and revokes old
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_persists_new_token_and_revokes_old():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        old_refresh = r.json()["refresh_token"]

        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert r.status_code == 200
        new_refresh = r.json()["refresh_token"]
        assert new_refresh != old_refresh

        # old token should be revoked
        old_stored = await adapter.get_refresh_token(old_refresh)
        assert old_stored is not None
        assert old_stored.revoked is True

        # new token should be stored
        new_stored = await adapter.get_refresh_token(new_refresh)
        assert new_stored is not None
        assert new_stored.revoked is False

        # same family
        assert old_stored.family_id == new_stored.family_id


# ---------------------------------------------------------------------------
# Refresh reuse detection — revokes entire family
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_reuse_blocked_by_blacklist():
    """Replaying an already-used refresh token is blocked (JTI blacklisted)."""
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        old_refresh = r.json()["refresh_token"]

        # first refresh — should succeed
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert r.status_code == 200

        # replay the OLD refresh token — blocked by blacklist
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_family_when_blacklist_lost():
    """If the blacklist lost the JTI (e.g. restart), DB reuse detection kicks in."""
    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        old_refresh = r.json()["refresh_token"]

        # first refresh — succeeds, old token revoked in DB
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert r.status_code == 200
        new_refresh = r.json()["refresh_token"]

        # simulate blacklist loss (e.g., server restart with InMemory)
        fullauth.token_engine.blacklist = type(fullauth.token_engine.blacklist)()

        # replay the old token — blacklist doesn't catch it,
        # but DB reuse detection revokes the family
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert r.status_code == 401

        # the new token's family should also be revoked
        new_stored = await adapter.get_refresh_token(new_refresh)
        assert new_stored is not None
        assert new_stored.revoked is True


# ---------------------------------------------------------------------------
# Concurrent refresh — second request must fail even with cleared blacklist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_reuse_caught_by_explicit_blacklist_check():
    """Even if decode_token doesn't catch it (e.g. race window), the explicit
    is_blacklisted guard before issuing new tokens rejects the second call."""
    from unittest.mock import patch

    app, adapter, fullauth = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        refresh_token = r.json()["refresh_token"]

        # first refresh succeeds normally
        r1 = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert r1.status_code == 200

        # simulate race: patch decode_token to skip the blacklist check
        # (as if two requests decoded in parallel before either blacklisted)
        original_decode = fullauth.token_engine.decode_token
        blacklist = fullauth.token_engine.blacklist

        async def decode_skipping_blacklist(token):
            # temporarily disable blacklist during decode
            fullauth.token_engine.blacklist = type(blacklist)()
            try:
                return await original_decode(token)
            finally:
                fullauth.token_engine.blacklist = blacklist

        with patch.object(fullauth.token_engine, "decode_token", decode_skipping_blacklist):
            r2 = await client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_token},
            )
        # the explicit is_blacklisted check in the route catches it
        assert r2.status_code == 401


# ---------------------------------------------------------------------------
# Refresh with REFRESH_TOKEN_ROTATION=False — returns same refresh token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_no_rotation():
    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            REFRESH_TOKEN_ROTATION=False,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        original_refresh = r.json()["refresh_token"]

        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        assert r.status_code == 200
        assert r.json()["refresh_token"] == original_refresh  # same token returned

        # can use it again (no rotation = reuse is fine)
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": original_refresh},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Logout revokes refresh token family
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_revokes_refresh_family():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        tokens = r.json()

        r = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert r.status_code == 204

        # refresh token family should be revoked
        stored = await adapter.get_refresh_token(tokens["refresh_token"])
        assert stored is not None
        assert stored.revoked is True


@pytest.mark.asyncio
async def test_logout_without_body_still_works():
    app, adapter, _ = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 204


# ---------------------------------------------------------------------------
# Redis blacklist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_blacklist_add_and_check():
    import fakeredis.aioredis

    from fastapi_fullauth.core.redis_blacklist import RedisBlacklist

    bl = RedisBlacklist.__new__(RedisBlacklist)
    bl._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    bl._default_ttl = 300
    bl._prefix = "fullauth:blacklist:"

    assert await bl.is_blacklisted("jti-123") is False
    await bl.add("jti-123")
    assert await bl.is_blacklisted("jti-123") is True
    assert await bl.is_blacklisted("jti-other") is False


@pytest.mark.asyncio
async def test_redis_blacklist_custom_ttl():
    import fakeredis.aioredis

    from fastapi_fullauth.core.redis_blacklist import RedisBlacklist

    bl = RedisBlacklist.__new__(RedisBlacklist)
    bl._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    bl._default_ttl = 300
    bl._prefix = "fullauth:blacklist:"

    await bl.add("jti-ttl", ttl_seconds=10)
    ttl = await bl._redis.ttl("fullauth:blacklist:jti-ttl")
    assert ttl <= 10
    assert ttl > 0


def test_redis_blacklist_requires_redis_package():
    """RedisBlacklist raises helpful ImportError if redis not installed."""
    import unittest.mock

    with unittest.mock.patch.dict("sys.modules", {"redis": None, "redis.asyncio": None}):
        # need to reimport to trigger the import check
        import importlib

        from fastapi_fullauth.core import redis_blacklist

        importlib.reload(redis_blacklist)
        with pytest.raises(ImportError, match="redis package is required"):
            redis_blacklist.RedisBlacklist("redis://localhost")
