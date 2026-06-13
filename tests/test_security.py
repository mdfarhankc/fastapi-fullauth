"""Tests for security middleware (security headers, CSRF, rate limiting) and
account lockout."""

import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth.middleware import CSRFMiddleware, SecurityHeadersMiddleware
from fastapi_fullauth.middleware.ratelimit import RateLimitMiddleware
from fastapi_fullauth.protection.lockout import InMemoryLockoutManager

# Security headers middleware


@pytest.fixture
def security_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_security_headers(security_app):
    transport = ASGITransport(app=security_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/test")
        assert r.status_code == 200
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-xss-protection"] == "0"
        assert "referrer-policy" in r.headers


@pytest.mark.asyncio
async def test_hsts_only_on_https():
    """HSTS must not be sent over plaintext HTTP (browsers ignore it there and a
    stray HTTP deploy could pin sibling subdomains), but is sent over HTTPS and
    when a proxy forwards an HTTPS scheme."""
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    transport = ASGITransport(app=app)
    # Plaintext HTTP: no HSTS.
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/test")
        assert "strict-transport-security" not in r.headers
        # ...unless a trusted proxy says the edge was HTTPS.
        r = await client.get("/test", headers={"x-forwarded-proto": "https"})
        assert "strict-transport-security" in r.headers

    # Direct HTTPS: HSTS present.
    async with AsyncClient(transport=transport, base_url="https://test") as client:
        r = await client.get("/test")
        assert "strict-transport-security" in r.headers


# CSRF middleware


@pytest.fixture
def csrf_app():
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, secret="test-csrf-secret-that-is-at-least-32-chars-long")

    @app.get("/form")
    async def form():
        return {"ok": True}

    @app.post("/submit")
    async def submit():
        return {"submitted": True}

    return app


@pytest.mark.asyncio
async def test_csrf_sets_cookie_on_get(csrf_app):
    transport = ASGITransport(app=csrf_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/form")
        assert r.status_code == 200
        assert "fullauth_csrf" in r.cookies


@pytest.mark.asyncio
async def test_csrf_blocks_post_without_token(csrf_app):
    transport = ASGITransport(app=csrf_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/submit")
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_csrf_allows_post_with_valid_token(csrf_app):
    transport = ASGITransport(app=csrf_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # get the csrf cookie
        r = await client.get("/form")
        csrf_token = r.cookies["fullauth_csrf"]

        # post with matching header and cookie
        client.cookies.set("fullauth_csrf", csrf_token)
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_csrf_rejects_wrong_token(csrf_app):
    transport = ASGITransport(app=csrf_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/form")
        client.cookies.set("fullauth_csrf", r.cookies["fullauth_csrf"])
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": "wrong-token"},
        )
        assert r.status_code == 403


def test_csrf_middleware_rejects_samesite_none_without_secure():
    """A SameSite=None CSRF cookie without Secure is dropped by browsers; reject
    the misconfiguration at construction."""

    async def _dummy_app(scope, receive, send):  # minimal ASGI app
        return None

    with pytest.raises(ValueError, match="cookie_secure=True"):
        CSRFMiddleware(
            _dummy_app,
            secret="test-csrf-secret-that-is-at-least-32-chars-long",
            cookie_samesite="none",
            cookie_secure=False,
        )


# Rate limit middleware


@pytest.fixture
def ratelimit_app():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, max_requests=3, window_seconds=60)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_rate_limit_allows_under_limit(ratelimit_app):
    transport = ASGITransport(app=ratelimit_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(3):
            r = await client.get("/test")
            assert r.status_code == 200
        assert "x-ratelimit-limit" in r.headers


@pytest.mark.asyncio
async def test_rate_limit_blocks_over_limit(ratelimit_app):
    transport = ASGITransport(app=ratelimit_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(3):
            await client.get("/test")
        r = await client.get("/test")
        assert r.status_code == 429


# Proxy header IP extraction


@pytest.mark.asyncio
async def test_rate_limit_uses_x_forwarded_for_when_trusted():
    """When TRUSTED_PROXY_HEADERS includes X-Forwarded-For, the middleware
    should rate-limit by the forwarded IP, not the direct client IP."""
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=2,
        window_seconds=60,
        trusted_proxy_headers=["X-Forwarded-For"],
    )

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 2 requests from "1.2.3.4" via header = should exhaust the limit
        for _ in range(2):
            r = await client.get("/test", headers={"X-Forwarded-For": "1.2.3.4"})
            assert r.status_code == 200

        # 3rd from same forwarded IP = blocked
        r = await client.get("/test", headers={"X-Forwarded-For": "1.2.3.4"})
        assert r.status_code == 429

        # different forwarded IP = still allowed
        r = await client.get("/test", headers={"X-Forwarded-For": "5.6.7.8"})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_ignores_proxy_header_when_not_trusted():
    """Without trusted headers configured, X-Forwarded-For is ignored."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, max_requests=2, window_seconds=60)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # all requests come from the same direct client IP regardless of header
        for _ in range(2):
            r = await client.get("/test", headers={"X-Forwarded-For": "1.2.3.4"})
            assert r.status_code == 200
        r = await client.get("/test", headers={"X-Forwarded-For": "5.6.7.8"})
        assert r.status_code == 429  # still blocked = header ignored


def test_get_client_ip_chain():
    """When X-Forwarded-For contains a chain, the first IP is returned."""
    from fastapi_fullauth.utils import get_client_ip

    request = MagicMock()
    request.headers = {"X-Forwarded-For": "1.1.1.1, 10.0.0.1, 10.0.0.2"}
    request.client.host = "127.0.0.1"
    assert get_client_ip(request, ["X-Forwarded-For"]) == "1.1.1.1"


def test_get_client_ip_falls_back_to_client_host():
    """Without trusted headers, falls back to request.client.host."""
    from fastapi_fullauth.utils import get_client_ip

    request = MagicMock()
    request.headers = {"X-Forwarded-For": "1.1.1.1"}
    request.client.host = "127.0.0.1"
    assert get_client_ip(request, []) == "127.0.0.1"
    assert get_client_ip(request, None) == "127.0.0.1"


def test_request_session_metadata_clamps_to_column_widths():
    """The client-controlled User-Agent (and a trusted-proxy IP) are clamped to
    the storage column widths so an oversized value can't overflow the column
    and 500 the login/refresh INSERT on strict databases."""
    from fastapi_fullauth.utils import request_session_metadata

    request = MagicMock()
    request.headers = {
        "user-agent": "A" * 1000,
        "X-Forwarded-For": "1" * 100,
    }
    request.client.host = "127.0.0.1"

    user_agent, ip_address = request_session_metadata(request, ["X-Forwarded-For"])
    assert user_agent == "A" * 512
    assert ip_address == "1" * 45


def test_request_session_metadata_passes_through_normal_values():
    """Values within the limits are returned unchanged; a missing User-Agent
    stays None rather than becoming an empty string."""
    from fastapi_fullauth.utils import request_session_metadata

    request = MagicMock()
    request.headers = {}
    request.client.host = "203.0.113.7"

    user_agent, ip_address = request_session_metadata(request, [])
    assert user_agent is None
    assert ip_address == "203.0.113.7"


# Redis rate limiter


@pytest.mark.asyncio
async def test_redis_rate_limiter_allows_and_blocks():
    import fakeredis.aioredis

    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 3
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    for _ in range(3):
        assert await limiter.is_allowed("test-ip") is True
    assert await limiter.is_allowed("test-ip") is False


@pytest.mark.asyncio
async def test_redis_rate_limiter_remaining():
    import fakeredis.aioredis

    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 5
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    await limiter.is_allowed("test-ip")
    await limiter.is_allowed("test-ip")
    assert await limiter.remaining("test-ip") == 3


@pytest.mark.asyncio
async def test_redis_rate_limiter_reset_time():
    import fakeredis.aioredis

    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 5
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    assert await limiter.reset_time("new-ip") == 0.0
    await limiter.is_allowed("new-ip")
    reset = await limiter.reset_time("new-ip")
    assert 0 < reset <= 60


@pytest.mark.asyncio
async def test_redis_rate_limiter_middleware():
    import fakeredis.aioredis

    from fastapi_fullauth.middleware.ratelimit import RateLimitMiddleware
    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 2
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(2):
            r = await client.get("/test")
            assert r.status_code == 200
        r = await client.get("/test")
        assert r.status_code == 429


@pytest.mark.asyncio
async def test_redis_rate_limiter_counts_hits_in_the_same_clock_tick():
    """Two requests landing in the same time.time() tick must both count. If the
    sorted-set member were the bare timestamp they'd collide and zadd would
    overwrite, letting the limit be exceeded under concurrency."""
    from unittest.mock import patch

    import fakeredis.aioredis

    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 3
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    # Freeze the clock so every hit shares one timestamp.
    with patch("fastapi_fullauth.protection.ratelimit.time.time", return_value=1000.0):
        for _ in range(3):
            assert await limiter.is_allowed("same-tick-ip") is True
        assert await limiter.is_allowed("same-tick-ip") is False


@pytest.mark.asyncio
async def test_redis_rate_limiter_fails_open_on_redis_error():
    """A Redis outage must not lock everyone out: the limiter allows the request."""
    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    class _BoomRedis:
        def pipeline(self):
            raise RuntimeError("redis down")

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 1
    limiter.window_seconds = 60
    limiter._redis = _BoomRedis()
    limiter._prefix = "fullauth:ratelimit:"

    assert await limiter.is_allowed("any-ip") is True


@pytest.mark.asyncio
async def test_redis_blacklist_fails_closed_on_redis_error():
    """A Redis outage must not let a possibly-revoked token through: treat as
    blacklisted."""
    from fastapi_fullauth.core.blacklist import RedisTokenBlacklist

    class _BoomRedis:
        async def exists(self, *args):
            raise RuntimeError("redis down")

    bl = RedisTokenBlacklist.__new__(RedisTokenBlacklist)
    bl._redis = _BoomRedis()
    bl._default_ttl = 1800
    bl._prefix = "fullauth:blacklist:"

    assert await bl.is_blacklisted("some-jti") is True


# Account lockout


@pytest.mark.asyncio
async def test_not_locked_initially():
    mgr = InMemoryLockoutManager(max_attempts=3, lockout_seconds=60)
    assert not await mgr.is_locked("user@test.com")


@pytest.mark.asyncio
async def test_locks_after_max_attempts():
    mgr = InMemoryLockoutManager(max_attempts=3, lockout_seconds=60)
    for _ in range(3):
        await mgr.record_failure("user@test.com")
    assert await mgr.is_locked("user@test.com")


@pytest.mark.asyncio
async def test_not_locked_before_max():
    mgr = InMemoryLockoutManager(max_attempts=3, lockout_seconds=60)
    await mgr.record_failure("user@test.com")
    await mgr.record_failure("user@test.com")
    assert not await mgr.is_locked("user@test.com")


@pytest.mark.asyncio
async def test_clear_resets_lockout():
    mgr = InMemoryLockoutManager(max_attempts=3, lockout_seconds=60)
    for _ in range(3):
        await mgr.record_failure("user@test.com")
    assert await mgr.is_locked("user@test.com")
    await mgr.clear("user@test.com")
    assert not await mgr.is_locked("user@test.com")


@pytest.mark.asyncio
async def test_lockout_expires():
    mgr = InMemoryLockoutManager(max_attempts=2, lockout_seconds=1)
    await mgr.record_failure("user@test.com")
    await mgr.record_failure("user@test.com")
    assert await mgr.is_locked("user@test.com")

    # fast-forward time
    with patch("fastapi_fullauth.protection.lockout.time") as mock_time:
        mock_time.monotonic.return_value = time.monotonic() + 2
        assert not await mgr.is_locked("user@test.com")


@pytest.mark.asyncio
async def test_separate_keys():
    mgr = InMemoryLockoutManager(max_attempts=2, lockout_seconds=60)
    await mgr.record_failure("a@test.com")
    await mgr.record_failure("a@test.com")
    assert await mgr.is_locked("a@test.com")
    assert not await mgr.is_locked("b@test.com")


# CSRF Origin allow-list and exempt-path anchoring


@pytest.fixture
def csrf_origin_app():
    app = FastAPI()
    app.add_middleware(
        CSRFMiddleware,
        secret="test-csrf-secret-that-is-at-least-32-chars-long",
        trusted_origins=["http://allowed.example"],
    )

    @app.get("/form")
    async def form():
        return {"ok": True}

    @app.post("/submit")
    async def submit():
        return {"submitted": True}

    return app


@pytest.mark.asyncio
async def test_csrf_rejects_untrusted_origin(csrf_origin_app):
    """Even with a valid double-submit token, a request whose Origin is not in
    trusted_origins is rejected - this is what stops a cookie-injecting attacker."""
    transport = ASGITransport(app=csrf_origin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        token = (await client.get("/form")).cookies["fullauth_csrf"]
        client.cookies.set("fullauth_csrf", token)
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": token, "Origin": "http://evil.example"},
        )
        assert r.status_code == 403
        assert "origin" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_csrf_allows_trusted_origin(csrf_origin_app):
    transport = ASGITransport(app=csrf_origin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        token = (await client.get("/form")).cookies["fullauth_csrf"]
        client.cookies.set("fullauth_csrf", token)
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": token, "Origin": "http://allowed.example"},
        )
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_csrf_allows_request_without_origin_header(csrf_origin_app):
    """A non-browser client sends no Origin/Referer; it must defer to the token
    check rather than be blocked outright."""
    transport = ASGITransport(app=csrf_origin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        token = (await client.get("/form")).cookies["fullauth_csrf"]
        client.cookies.set("fullauth_csrf", token)
        r = await client.post("/submit", headers={"X-CSRF-Token": token})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_csrf_exempt_paths_are_segment_anchored():
    """Exempting '/api/foo' must not also exempt '/api/foobar'."""
    app = FastAPI()
    app.add_middleware(
        CSRFMiddleware,
        secret="test-csrf-secret-that-is-at-least-32-chars-long",
        exempt_paths=["/api/foo"],
    )

    @app.post("/api/foo")
    async def foo():
        return {"ok": True}

    @app.post("/api/foobar")
    async def foobar():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # exact exempt path bypasses CSRF entirely
        assert (await client.post("/api/foo")).status_code == 200
        # a sibling that merely shares the prefix is NOT exempt -> blocked (no token)
        assert (await client.post("/api/foobar")).status_code == 403


@pytest.mark.asyncio
async def test_redis_rate_limiter_enforces_limit_under_concurrency():
    """The atomic check-and-add must not let a concurrent burst exceed the limit
    (the old check-then-add was a TOCTOU race)."""
    import asyncio

    import fakeredis.aioredis

    from fastapi_fullauth.protection.ratelimit import RedisRateLimiter

    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.max_requests = 3
    limiter.window_seconds = 60
    limiter._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter._prefix = "fullauth:ratelimit:"

    results = await asyncio.gather(*[limiter.is_allowed("burst-ip") for _ in range(20)])
    # Never more than the limit may be admitted, no matter the interleaving.
    assert sum(results) <= 3
    # And it does admit up to the limit (not trivially rejecting everything).
    assert sum(results) == 3
    # The stored set never holds more than the limit either.
    assert await limiter._redis.zcard("fullauth:ratelimit:burst-ip") == 3
