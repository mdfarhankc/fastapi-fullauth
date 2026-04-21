"""Tests for authentication flows: register, login, logout, refresh tokens, email
verification, password reset, token expiry, and auth rate limiting."""

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.dependencies import current_user
from tests.conftest import User


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


async def _make_app(adapter=None, **fullauth_kwargs):
    """Helper to build a test app with given FullAuth config."""
    engine, session_maker = await _make_db()
    adapter = adapter or SQLModelAdapter(session_maker=session_maker, user_model=User)
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
    return app, adapter, fullauth, engine


# ===========================================================================
# Basic auth flows (register, login, logout, /me)
# ===========================================================================


@pytest.mark.asyncio
async def test_register(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "new@test.com", "password": "securepass123"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == "new@test.com"
    assert data["is_active"] is True
    assert data["is_verified"] is False


@pytest.mark.asyncio
async def test_register_duplicate(client, registered_user):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_register_anti_enumeration_same_response_for_new_and_existing():
    """Opt-in PREVENT_REGISTRATION_ENUMERATION=True: new and duplicate emails
    produce identical 202 responses so the endpoint can't be used to probe
    whether an email is registered."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            PREVENT_REGISTRATION_ENUMERATION=True,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/api/v1/auth/register",
            json={"email": "new@test.com", "password": "securepass123"},
        )
        second = await client.post(
            "/api/v1/auth/register",
            json={"email": "new@test.com", "password": "securepass123"},
        )

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json() == second.json()

    await engine.dispose()


@pytest.mark.asyncio
async def test_register_weak_password(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@test.com", "password": "short"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "wrongpassword"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@test.com", "password": "whatever123"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_locked_account_returns_generic_credentials_error():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            MAX_LOGIN_ATTEMPTS=2,
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "locked@test.com", "password": "securepass123"},
        )
        for _ in range(2):
            await client.post(
                "/api/v1/auth/login",
                json={"email": "locked@test.com", "password": "wrong"},
            )
        # account is now locked — even the correct password must look identical
        # to "wrong password" (401 + generic detail), not 423 or a locked-specific body
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "locked@test.com", "password": "securepass123"},
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"

    await engine.dispose()


@pytest.mark.asyncio
async def test_me_authenticated(client, auth_headers):
    r = await client.get("/me", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["email"] == "user@test.com"


@pytest.mark.asyncio
async def test_me_no_token(client):
    r = await client.get("/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_invalid_token(client):
    r = await client.get("/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout(client, auth_headers, login_tokens):
    r = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert r.status_code == 204

    # token should be blacklisted now
    r = await client.get("/me", headers=auth_headers)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh(client, login_tokens):
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["access_token"] != login_tokens["access_token"]


@pytest.mark.asyncio
async def test_refresh_reuse_blocked(client, login_tokens):
    # first refresh works
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 200

    # second use of same refresh token should fail (blacklisted)
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_access_token_fails(client, login_tokens):
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["access_token"]},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_flow(client, registered_user, fullauth):
    # request reset
    r = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "user@test.com"},
    )
    assert r.status_code == 202

    # generate token manually for testing (normally sent via email)
    from fastapi_fullauth.flows.password_reset import request_password_reset

    token = await request_password_reset(fullauth.adapter, fullauth.token_engine, "user@test.com")
    assert token is not None

    # confirm reset
    r = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "newpassword123"},
    )
    assert r.status_code == 200

    # login with new password
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "newpassword123"},
    )
    assert r.status_code == 200

    # old password should fail
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_nonexistent_user(client):
    r = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "nobody@test.com"},
    )
    # should still return 202 to prevent enumeration
    assert r.status_code == 202


# ===========================================================================
# Refresh token persistence, reuse detection, and Redis blacklist
# ===========================================================================


@pytest.mark.asyncio
async def test_login_persists_refresh_token():
    app, adapter, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_persists_new_token_and_revokes_old():
    app, adapter, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_reuse_blocked_by_blacklist():
    """Replaying an already-used refresh token is blocked (JTI blacklisted)."""
    app, adapter, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_family_when_blacklist_lost():
    """If the blacklist lost the JTI (e.g. restart), DB reuse detection kicks in."""
    app, adapter, fullauth, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_reuse_caught_by_explicit_blacklist_check():
    """Even if decode_token doesn't catch it (e.g. race window), the explicit
    is_blacklisted guard before issuing new tokens rejects the second call."""
    from unittest.mock import patch

    app, adapter, fullauth, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_no_rotation():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_logout_revokes_refresh_family():
    app, adapter, _, engine = await _make_app()
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_logout_without_body_still_works():
    app, adapter, _, engine = await _make_app()
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

    await engine.dispose()


# ===========================================================================
# Redis blacklist
# ===========================================================================


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


# ===========================================================================
# Email verification
# ===========================================================================


@pytest.fixture
def sent_emails():
    return []


@pytest.fixture
async def verify_app(sent_emails):
    async def mock_send(email: str, token: str):
        sent_emails.append({"email": email, "token": token})

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)
    fullauth.hooks.on("send_verification_email", mock_send)
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return user

    yield app
    await engine.dispose()


@pytest.fixture
async def verify_client(verify_app):
    transport = ASGITransport(app=verify_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _register_and_login_verify(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "verify@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "verify@test.com", "password": "securepass123"},
    )
    return r.json()


@pytest.mark.asyncio
async def test_verify_email_full_flow(verify_client, sent_emails):
    tokens = await _register_and_login_verify(verify_client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    # not verified yet
    r = await verify_client.get("/me", headers=headers)
    assert r.json()["is_verified"] is False

    # request verification
    r = await verify_client.post("/api/v1/auth/verify-email/request", headers=headers)
    assert r.status_code == 202
    assert len(sent_emails) == 1
    assert sent_emails[0]["email"] == "verify@test.com"

    # confirm
    r = await verify_client.post(
        "/api/v1/auth/verify-email/confirm",
        json={"token": sent_emails[0]["token"]},
    )
    assert r.status_code == 200

    # now verified
    r = await verify_client.get("/me", headers=headers)
    assert r.json()["is_verified"] is True


@pytest.mark.asyncio
async def test_verify_token_single_use(verify_client, sent_emails):
    tokens = await _register_and_login_verify(verify_client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    await verify_client.post("/api/v1/auth/verify-email/request", headers=headers)
    verify_token = sent_emails[0]["token"]

    # first use works
    r = await verify_client.post(
        "/api/v1/auth/verify-email/confirm",
        json={"token": verify_token},
    )
    assert r.status_code == 200

    # second use fails
    r = await verify_client.post(
        "/api/v1/auth/verify-email/confirm",
        json={"token": verify_token},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_verify_invalid_token(verify_client):
    r = await verify_client.post(
        "/api/v1/auth/verify-email/confirm",
        json={"token": "garbage"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_verify_without_callback(client, auth_headers):
    """No email callback configured — request still returns 202 but no email sent."""
    r = await client.post("/api/v1/auth/verify-email/request", headers=auth_headers)
    assert r.status_code == 202


# ===========================================================================
# expires_in in token response
# ===========================================================================


@pytest.mark.asyncio
async def test_login_returns_expires_in():
    app, _, _, engine = await _make_app()
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
        assert "expires_in" in tokens
        assert tokens["expires_in"] == 30 * 60  # default 30 minutes

    await engine.dispose()


@pytest.mark.asyncio
async def test_refresh_returns_expires_in():
    app, _, _, engine = await _make_app()
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
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert r.status_code == 200
        assert r.json()["expires_in"] == 30 * 60

    await engine.dispose()


# ===========================================================================
# Auth route rate limiting
# ===========================================================================


@pytest.mark.asyncio
async def test_login_rate_limited():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=True,
            AUTH_RATE_LIMIT_LOGIN=2,
            AUTH_RATE_LIMIT_WINDOW_SECONDS=60,
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

        # first 2 login attempts should work (even if wrong password)
        for _ in range(2):
            await client.post(
                "/api/v1/auth/login",
                json={"email": "t@t.com", "password": "securepass123"},
            )

        # 3rd should be rate limited
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        assert r.status_code == 429

    await engine.dispose()


@pytest.mark.asyncio
async def test_register_rate_limited():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=True,
            AUTH_RATE_LIMIT_REGISTER=1,
            AUTH_RATE_LIMIT_WINDOW_SECONDS=60,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "a@t.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "b@t.com", "password": "securepass123"},
        )
        assert r.status_code == 429

    await engine.dispose()
