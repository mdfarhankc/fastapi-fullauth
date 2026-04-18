"""Tests for configuration, composable routers, custom schemas, password validators,
custom token claims, auto-wired middleware, flat config, and adapter-level schemas."""

import sys
import warnings

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig, PasswordValidator
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.dependencies import current_user
from fastapi_fullauth.types import CreateUserSchema, UserSchema
from tests.conftest import User


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    return engine, session_maker


# ===========================================================================
# Password validators
# ===========================================================================


def test_password_validator_min_length():
    v = PasswordValidator(min_length=10)
    from fastapi_fullauth.exceptions import InvalidPasswordError

    with pytest.raises(InvalidPasswordError):
        v.validate("short")


def test_password_validator_require_uppercase():
    v = PasswordValidator(require_uppercase=True)
    from fastapi_fullauth.exceptions import InvalidPasswordError

    with pytest.raises(InvalidPasswordError):
        v.validate("alllowercase123")

    v.validate("HasUppercase123")  # should pass


def test_password_validator_require_digit():
    v = PasswordValidator(require_digit=True)
    from fastapi_fullauth.exceptions import InvalidPasswordError

    with pytest.raises(InvalidPasswordError):
        v.validate("nodigitshere")

    v.validate("hasdigit1")  # should pass


def test_password_validator_blocked_passwords():
    v = PasswordValidator(blocked_passwords=["password123", "qwerty123"])
    from fastapi_fullauth.exceptions import InvalidPasswordError

    with pytest.raises(InvalidPasswordError):
        v.validate("password123")

    with pytest.raises(InvalidPasswordError):
        v.validate("QWERTY123")  # case-insensitive


@pytest.mark.asyncio
async def test_register_rejects_weak_password_via_validator():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        password_validator=PasswordValidator(
            min_length=8, require_uppercase=True, require_digit=True
        ),
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # weak: no uppercase, no digit
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "alllowercase"},
        )
        assert r.status_code == 422

        # strong: has uppercase and digit
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "Strong1pass"},
        )
        assert r.status_code == 201

    await engine.dispose()


# ===========================================================================
# Composable routers
# ===========================================================================


@pytest.mark.asyncio
async def test_composable_router_excludes_register():
    """Including only auth_router still works; skipping it means no register route."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)

    app = FastAPI()
    app.state.fullauth = fullauth
    # only include profile router, not auth router
    app.include_router(fullauth.profile_router, prefix="/api/v1/auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "securepass123"},
        )
        assert r.status_code == 404

    await engine.dispose()


@pytest.mark.asyncio
async def test_composable_routers_exclude_register():
    """Only including specific routers means excluded routes return 404."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_me_route_excluded_with_composable_routers():
    """Including only auth_router means /me is not available."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
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

    await engine.dispose()


# ===========================================================================
# Custom CreateUserSchema
# ===========================================================================


@pytest.mark.asyncio
async def test_custom_create_user_schema():
    class MyCreateSchema(CreateUserSchema):
        display_name: str

    class MyUserSchema(UserSchema):
        display_name: str | None = None

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        user_schema=MyUserSchema,
        create_user_schema=MyCreateSchema,
    )
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "custom@test.com",
                "password": "securepass123",
                "display_name": "John",
            },
        )
        assert r.status_code == 201
        assert r.json()["display_name"] == "John"

    await engine.dispose()


@pytest.mark.asyncio
async def test_custom_schema_rejects_missing_field():
    class MyCreateSchema(CreateUserSchema):
        display_name: str

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        create_user_schema=MyCreateSchema,
    )
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # missing display_name should fail
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "securepass123"},
        )
        assert r.status_code == 422

    await engine.dispose()


# ===========================================================================
# Custom token claims
# ===========================================================================


@pytest.mark.asyncio
async def test_custom_token_claims():

    async def add_claims(user):
        return {"org_id": "org-123", "plan": "pro"}

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        on_create_token_claims=add_claims,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/claims")
    async def get_claims(
        request: Request,
    ):
        from fastapi_fullauth.dependencies.current_user import _get_fullauth

        fa = _get_fullauth(request)
        token = request.headers["authorization"].split(" ")[1]
        payload = await fa.token_engine.decode_token(token)
        return payload.extra

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "claims@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "claims@test.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.get("/claims", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["org_id"] == "org-123"
        assert data["plan"] == "pro"

    await engine.dispose()


# ===========================================================================
# Login response with user
# ===========================================================================


@pytest.mark.asyncio
async def test_login_includes_user():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        INCLUDE_USER_IN_LOGIN=True,
    )
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "user@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "user@test.com", "password": "securepass123"},
        )
        data = r.json()
        assert "access_token" in data
        assert "user" in data
        assert data["user"]["email"] == "user@test.com"

    await engine.dispose()


@pytest.mark.asyncio
async def test_login_excludes_user_by_default(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    data = r.json()
    assert "access_token" in data
    assert data["user"] is None


# ===========================================================================
# Auto-generate SECRET_KEY
# ===========================================================================


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


# ===========================================================================
# Flat config
# ===========================================================================


@pytest.mark.asyncio
async def test_flat_config_secret_key():
    """FullAuth(adapter=..., config=FullAuthConfig(SECRET_KEY=...)) passes key via config."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(SECRET_KEY="flat-config-key-32b-long!!!!!!!!!"),
    )
    assert fullauth.config.SECRET_KEY == "flat-config-key-32b-long!!!!!!!!!"
    await engine.dispose()


@pytest.mark.asyncio
async def test_flat_config_with_extras():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(
            SECRET_KEY="flat-config-key-32b-long!!!!!!!!!",
            API_PREFIX="/v2",
        ),
    )
    assert fullauth.config.API_PREFIX == "/v2"
    await engine.dispose()


@pytest.mark.asyncio
async def test_no_config_auto_generates_key():
    """FullAuth(adapter=...) with no secret_key still works (auto-generate)."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        fullauth = FullAuth(adapter=adapter)
        assert fullauth.config.SECRET_KEY is not None
    await engine.dispose()


# ===========================================================================
# Auto-wire middleware
# ===========================================================================


@pytest.mark.asyncio
async def test_auto_security_headers():
    """Security headers are injected when INJECT_SECURITY_HEADERS=True."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_auto_middleware_false_skips():
    """auto_middleware=False skips all auto-wired middleware."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
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

    await engine.dispose()


# ===========================================================================
# Built-in /me route
# ===========================================================================


@pytest.mark.asyncio
async def test_builtin_me_route():
    """The /me route is available out of the box."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
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

    await engine.dispose()


# ===========================================================================
# Typed dependency returns
# ===========================================================================


@pytest.mark.skipif(
    sys.version_info < (3, 14),
    reason="annotationlib requires Python 3.14+",
)
def test_current_user_has_return_annotation():
    """current_user dependency has a UserSchema return type for IDE support."""
    import annotationlib

    ann = annotationlib.get_annotations(current_user, format=annotationlib.Format.STRING)
    assert ann.get("return") == "UserSchema"


# ===========================================================================
# Adapter-level schema configuration
# ===========================================================================


@pytest.mark.asyncio
async def test_default_create_schema_on_adapter():
    """When no create_user_schema is given, adapter defaults to CreateUserSchema."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    assert adapter._create_user_schema is CreateUserSchema
    await engine.dispose()


@pytest.mark.asyncio
async def test_explicit_schemas_on_adapter():
    """Schemas are passed to the adapter, FullAuth reads them from there."""

    class MyCreate(CreateUserSchema):
        display_name: str

    class MyUser(UserSchema):
        display_name: str | None = None

    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        user_schema=MyUser,
        create_user_schema=MyCreate,
    )
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
                "display_name": "tester",
            },
        )
        assert r.status_code == 201
        assert r.json()["display_name"] == "tester"

    await engine.dispose()


# ===========================================================================
# Init idempotency
# ===========================================================================


@pytest.mark.asyncio
async def test_init_app_twice_is_a_noop_with_warning():
    """Calling init_app a second time must warn and not duplicate routes/middleware."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(SECRET_KEY="test-key-32b-long-enough-here!!!"),
    )
    app = FastAPI()

    fullauth.init_app(app)
    routes_before = len(app.routes)
    middleware_before = len(app.user_middleware)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fullauth.init_app(app)
    assert any("init_app() called more than once" in str(w.message) for w in caught)

    assert len(app.routes) == routes_before
    assert len(app.user_middleware) == middleware_before

    await engine.dispose()


@pytest.mark.asyncio
async def test_init_middleware_twice_is_a_noop_with_warning():
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            CSRF_ENABLED=True,
        ),
    )
    app = FastAPI()

    fullauth.init_middleware(app)
    middleware_before = len(app.user_middleware)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fullauth.init_middleware(app)
    assert any("init_middleware() called more than once" in str(w.message) for w in caught)
    assert len(app.user_middleware) == middleware_before

    await engine.dispose()


@pytest.mark.asyncio
async def test_init_app_then_init_middleware_does_not_double_wire():
    """init_app(auto_middleware=True) already wires middleware; an extra
    init_middleware() call must be a warning-only no-op."""
    engine, session_maker = await _make_db()
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        adapter=adapter,
        config=FullAuthConfig(
            SECRET_KEY="test-key-32b-long-enough-here!!!",
            CSRF_ENABLED=True,
        ),
    )
    app = FastAPI()

    fullauth.init_app(app)
    middleware_after_init_app = len(app.user_middleware)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fullauth.init_middleware(app)
    assert any("init_middleware() called more than once" in str(w.message) for w in caught)
    assert len(app.user_middleware) == middleware_after_init_app

    await engine.dispose()
