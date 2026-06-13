"""Tests for the cookie auth backend, including refresh-token cookie transport."""

import pytest
from fastapi import Depends, FastAPI, Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.backends.cookie import CookieBackend
from fastapi_fullauth.dependencies import current_user
from tests.conftest import make_test_adapter


def _set_cookie_headers(response: Response) -> list[str]:
    return [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]


def _httpx_set_cookies(response) -> list[str]:
    """set-cookie headers off an httpx response (integration tests)."""
    return response.headers.get_list("set-cookie")


def test_cookie_backend_rejects_samesite_none_without_secure():
    """A SameSite=None cookie without Secure is dropped by browsers; reject the
    misconfiguration at construction instead of silently breaking auth."""
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    with pytest.raises(ValueError, match="secure=True"):
        CookieBackend(config, samesite="none", secure=False)


@pytest.mark.asyncio
async def test_delete_token_matches_write_token_attributes():
    """Both set-cookies (write and delete) must share secure/samesite/path/domain
    so browsers actually honour the deletion."""
    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
    )
    backend = CookieBackend(
        config,
        secure=True,
        httponly=True,
        samesite="none",
        domain="example.com",
    )

    write = Response()
    await backend.write_token(write, "some.jwt.token")
    delete = Response()
    await backend.delete_token(delete)

    write_header = _set_cookie_headers(write)[0].lower()
    delete_header = _set_cookie_headers(delete)[0].lower()

    for marker in ("secure", "samesite=none", "httponly", "domain=example.com", "path=/"):
        assert marker in write_header, f"write missing {marker}: {write_header}"
        assert marker in delete_header, f"delete missing {marker}: {delete_header}"

    # deletion is marked by max-age=0
    assert "max-age=0" in delete_header


@pytest.mark.asyncio
async def test_delete_token_with_default_samesite():
    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
    )
    backend = CookieBackend(config)

    response = Response()
    await backend.delete_token(response)
    header = _set_cookie_headers(response)[0].lower()

    assert "samesite=lax" in header
    assert "secure" in header
    assert "max-age=0" in header


# Refresh-token cookie transport — unit


@pytest.mark.asyncio
async def test_refresh_cookie_write_and_delete_share_attributes():
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    backend = CookieBackend(config, refresh_path="/api/v1/auth", samesite="strict")

    write = Response()
    await backend.write_refresh_token(write, "some.refresh.jwt")
    delete = Response()
    await backend.delete_refresh_token(delete)

    write_header = _set_cookie_headers(write)[0].lower()
    delete_header = _set_cookie_headers(delete)[0].lower()

    for marker in (
        "fullauth_refresh=",
        "secure",
        "samesite=strict",
        "httponly",
        "path=/api/v1/auth",
    ):
        assert marker in write_header, f"write missing {marker}: {write_header}"
    for marker in ("secure", "samesite=strict", "httponly", "path=/api/v1/auth"):
        assert marker in delete_header, f"delete missing {marker}: {delete_header}"
    assert "max-age=0" in delete_header


def test_cookie_backend_handles_refresh_and_bearer_does_not():
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    assert CookieBackend(config).handles_refresh_token is True
    assert BearerBackend().handles_refresh_token is False


# Refresh-token cookie transport — integration


async def _cookie_app(**backend_kwargs):
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    adapter = make_test_adapter(session_maker)
    # secure=False so httpx sends the cookies back over http:// in tests.
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        backends=[CookieBackend(config, secure=False, **backend_kwargs)],
    )
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return {"id": str(user.id)}

    return app, engine


def _names(response) -> set[str]:
    return {h.split("=", 1)[0] for h in _httpx_set_cookies(response)}


@pytest.mark.asyncio
async def test_cookie_login_sets_both_cookies_and_nulls_body():
    app, engine = await _cookie_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "c@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "c@test.com", "password": "securepass123"},
        )
        assert r.status_code == 200
        # refresh token must NOT be in the JSON body in cookie mode
        assert r.json()["refresh_token"] is None
        # both cookies set
        assert {"fullauth_access", "fullauth_refresh"} <= _names(r)
        assert client.cookies.get("fullauth_refresh")

        # the access cookie alone authenticates a protected route (no header)
        me = await client.get("/me")
        assert me.status_code == 200
    await engine.dispose()


@pytest.mark.asyncio
async def test_cookie_refresh_uses_cookie_and_rotates_both():
    app, engine = await _cookie_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "c@test.com", "password": "securepass123"},
        )
        await client.post(
            "/api/v1/auth/login",
            json={"email": "c@test.com", "password": "securepass123"},
        )
        old_refresh = client.cookies.get("fullauth_refresh")

        # no body at all — the route must read the refresh cookie
        r = await client.post("/api/v1/auth/refresh")
        assert r.status_code == 200
        assert r.json()["refresh_token"] is None
        # both cookies re-issued, and the refresh cookie rotated
        assert {"fullauth_access", "fullauth_refresh"} <= _names(r)
        assert client.cookies.get("fullauth_refresh") != old_refresh
    await engine.dispose()


@pytest.mark.asyncio
async def test_cookie_logout_clears_both_cookies():
    app, engine = await _cookie_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "c@test.com", "password": "securepass123"},
        )
        await client.post(
            "/api/v1/auth/login",
            json={"email": "c@test.com", "password": "securepass123"},
        )

        r = await client.post("/api/v1/auth/logout")
        assert r.status_code == 204
        deletions = [h.lower() for h in _httpx_set_cookies(r)]
        assert any("fullauth_access" in h and "max-age=0" in h for h in deletions)
        assert any("fullauth_refresh" in h and "max-age=0" in h for h in deletions)

        # cookies cleared from the jar -> protected route now rejects
        me = await client.get("/me")
        assert me.status_code in (401, 403)
    await engine.dispose()


@pytest.mark.asyncio
async def test_bearer_mode_keeps_refresh_token_in_body():
    """Regression guard: the default bearer transport still returns the refresh
    token in the JSON body and refreshes from the body."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=make_test_adapter(session_maker))
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "b@test.com", "password": "securepass123"},
        )
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "b@test.com", "password": "securepass123"},
        )
        refresh_token = login.json()["refresh_token"]
        assert isinstance(refresh_token, str)
        assert "fullauth_refresh" not in _names(login)

        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert r.status_code == 200
        assert isinstance(r.json()["refresh_token"], str)
    await engine.dispose()
