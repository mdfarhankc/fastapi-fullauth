"""Tests for the 6 DX improvements."""

import sys
import warnings

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import current_user
from fastapi_fullauth.types import CreateUserSchema, UserSchema


@pytest.mark.asyncio
async def test_composable_routers_exclude_register():
    """Only including specific routers means excluded routes return 404."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(SECRET_KEY="test-key-32b-long-enough-here!!!"),
    )
    app = FastAPI()
    app.state.fullauth = fullauth
    # only include profile, not auth — so no register/login
    app.include_router(fullauth.profile_router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "t@t.com", "password": "securepass123"},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# 2. Auto-generate SECRET_KEY
# ---------------------------------------------------------------------------


def test_auto_generate_secret_key():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        config = FullAuthConfig()
        assert config.SECRET_KEY is not None
        assert len(config.SECRET_KEY) > 0
        assert any("FULLAUTH_SECRET_KEY is not set" in str(x.message) for x in w)


def test_explicit_secret_key_no_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        config = FullAuthConfig(SECRET_KEY="my-explicit-key")
        assert config.SECRET_KEY == "my-explicit-key"
        assert not any("FULLAUTH_SECRET_KEY" in str(x.message) for x in w)


# ---------------------------------------------------------------------------
# 3. Email callbacks via hooks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_email_callback_via_hooks():
    """Register email callback via hooks.on() instead of constructor param."""
    sent = []

    async def on_reset(email, token):
        sent.append({"email": email, "token": token})

    adapter = InMemoryAdapter()
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
    )
    fullauth.hooks.on("send_password_reset_email", on_reset)

    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "hook@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "hook@test.com"},
        )
        assert r.status_code == 202
        assert len(sent) == 1
        assert sent[0]["email"] == "hook@test.com"


# ---------------------------------------------------------------------------
# 4. Flat config
# ---------------------------------------------------------------------------


def test_flat_config_secret_key():
    """FullAuth(adapter=..., config=FullAuthConfig(SECRET_KEY=...)) passes key via config."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(SECRET_KEY="flat-config-key-32b-long!!!!!!!!!"),
    )
    assert fullauth.config.SECRET_KEY == "flat-config-key-32b-long!!!!!!!!!"


def test_flat_config_with_extras():
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(
            SECRET_KEY="flat-config-key-32b-long!!!!!!!!!",
            API_PREFIX="/v2",
        ),
    )
    assert fullauth.config.API_PREFIX == "/v2"


def test_no_config_auto_generates_key():
    """FullAuth(adapter=...) with no secret_key still works (auto-generate)."""
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        fullauth = FullAuth(adapter=InMemoryAdapter())
        assert fullauth.config.SECRET_KEY is not None


# ---------------------------------------------------------------------------
# 5. Auto-wire middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_security_headers():
    """Security headers are injected when INJECT_SECURITY_HEADERS=True."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            INJECT_SECURITY_HEADERS=True,
        ),
    )
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/ping")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"


@pytest.mark.asyncio
async def test_auto_middleware_false_skips():
    """auto_middleware=False skips all auto-wired middleware."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            INJECT_SECURITY_HEADERS=True,
        ),
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/ping")
        assert r.headers.get("x-content-type-options") is None


# ---------------------------------------------------------------------------
# Built-in /me route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_builtin_me_route():
    """The /me route is available out of the box."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            INJECT_SECURITY_HEADERS=False,
        ),
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "me@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "me@test.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["email"] == "me@test.com"


@pytest.mark.asyncio
async def test_me_route_excluded_with_composable_routers():
    """Including only auth_router means /me is not available."""
    fullauth = FullAuth(
        adapter=InMemoryAdapter(),
        config=FullAuthConfig(SECRET_KEY="test-key-32b-long-enough-here!!!"),
    )
    app = FastAPI()
    app.state.fullauth = fullauth
    # only include auth router (login/register/logout/refresh), not profile
    app.include_router(fullauth.auth_router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "me@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "me@test.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Typed dependency returns
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.version_info < (3, 14),
    reason="annotationlib requires Python 3.14+",
)
def test_current_user_has_return_annotation():
    """current_user dependency has a UserSchema return type for IDE support."""
    import annotationlib

    ann = annotationlib.get_annotations(current_user, format=annotationlib.Format.STRING)
    assert ann.get("return") == "UserSchema"


# ---------------------------------------------------------------------------
# 6. Adapter-level schema configuration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_create_schema_on_adapter():
    """When no create_user_schema is given, adapter defaults to CreateUserSchema."""
    adapter = InMemoryAdapter()
    assert adapter._create_user_schema is CreateUserSchema


@pytest.mark.asyncio
async def test_explicit_schemas_on_adapter():
    """Schemas are passed to the adapter, FullAuth reads them from there."""

    class MyCreate(CreateUserSchema):
        nickname: str

    class MyUser(UserSchema):
        nickname: str | None = None

    adapter = InMemoryAdapter(user_schema=MyUser, create_user_schema=MyCreate)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(SECRET_KEY="test-key-32b-long-enough-here!!!"),
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@test.com",
                "password": "securepass123",
                "nickname": "tester",
            },
        )
        assert r.status_code == 201
        assert r.json()["nickname"] == "tester"
