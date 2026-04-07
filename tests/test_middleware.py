import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth.middleware import CSRFMiddleware, SecurityHeadersMiddleware
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware


@pytest.fixture
def security_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_route():
        return {"ok": True}

    return app


@pytest.fixture
def csrf_app():
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, secret="test-csrf-secret-32bytes-long!!")

    @app.get("/form")
    async def form():
        return {"ok": True}

    @app.post("/submit")
    async def submit():
        return {"submitted": True}

    return app


@pytest.fixture
def ratelimit_app():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, max_requests=3, window_seconds=60)

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
        assert "strict-transport-security" in r.headers
        assert "referrer-policy" in r.headers


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
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": csrf_token},
            cookies={"fullauth_csrf": csrf_token},
        )
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_csrf_rejects_wrong_token(csrf_app):
    transport = ASGITransport(app=csrf_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/form")
        r = await client.post(
            "/submit",
            headers={"X-CSRF-Token": "wrong-token"},
            cookies={"fullauth_csrf": r.cookies["fullauth_csrf"]},
        )
        assert r.status_code == 403


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


# ── Redis rate limiter ───────────────────────────────────────────────


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

    from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware, RedisRateLimiter

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
