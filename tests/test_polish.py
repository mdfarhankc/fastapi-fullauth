"""Tests for small polish items: bearer case, require_role without roles field,
bcrypt length limit, SQLModel hashed_password column type, passkey config validation."""

import importlib.util

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.backends.bearer import BearerBackend
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import InvalidPasswordError
from tests.conftest import User

_has_bcrypt = importlib.util.find_spec("bcrypt") is not None

# ── Bearer header case-insensitivity ────────────────────────────────


@pytest.mark.asyncio
async def test_bearer_accepts_lowercase_scheme():
    backend = BearerBackend()

    async def _read(auth_header: str | None) -> str | None:
        scope = {
            "type": "http",
            "headers": [(b"authorization", auth_header.encode())] if auth_header else [],
        }
        request = Request(scope)
        return await backend.read_token(request)

    assert await _read("Bearer abc") == "abc"
    assert await _read("bearer abc") == "abc"
    assert await _read("BEARER abc") == "abc"
    assert await _read("bEaReR abc") == "abc"
    assert await _read("Basic abc") is None
    assert await _read(None) is None


# ── require_role tolerates missing roles field ──────────────────────


@pytest.mark.asyncio
async def test_require_role_returns_403_when_user_has_no_roles_field():
    """The default UserSchema has no `roles` field. require_role should return
    a clean 403, not AttributeError."""
    from fastapi import Depends

    from fastapi_fullauth.dependencies import current_user, require_role

    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    adapter = SQLModelAdapter(session_maker=session_maker, user_model=User)
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
        ),
        adapter=adapter,
    )
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

    @app.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    async def admin_only(user=Depends(current_user)):
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "u@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "u@test.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    await engine.dispose()


# ── bcrypt 72-byte limit ────────────────────────────────────────────


def test_bcrypt_rejects_passwords_over_72_bytes():
    # length check happens before `import bcrypt` so this works even without bcrypt installed
    with pytest.raises(InvalidPasswordError, match="bcrypt passwords must be at most"):
        hash_password("x" * 73, algorithm="bcrypt")


@pytest.mark.skipif(not _has_bcrypt, reason="bcrypt not installed")
def test_bcrypt_accepts_exactly_72_bytes():
    assert hash_password("x" * 72, algorithm="bcrypt").startswith("$2b$")


def test_argon2_accepts_long_passwords():
    # argon2id handles arbitrary length
    hash_password("x" * 500, algorithm="argon2id")


# ── SQLModel hashed_password column is Text ─────────────────────────


def test_sqlmodel_hashed_password_is_text_column():
    from sqlalchemy import Text

    from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase

    col = UserBase.model_fields["hashed_password"].sa_column  # type: ignore[attr-defined]
    assert isinstance(col.type, Text)


# ── Passkey config validation at construction time ──────────────────


def test_passkey_enabled_without_rp_id_fails_at_config():
    with pytest.raises(ValueError, match="PASSKEY_RP_ID is required"):
        FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            PASSKEY_ENABLED=True,
        )


def test_passkey_enabled_without_origins_fails_at_config():
    with pytest.raises(ValueError, match="PASSKEY_ORIGINS is required"):
        FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            PASSKEY_ENABLED=True,
            PASSKEY_RP_ID="example.com",
        )


def test_passkey_rp_id_with_scheme_fails_at_config():
    with pytest.raises(ValueError, match="must be a bare domain"):
        FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            PASSKEY_ENABLED=True,
            PASSKEY_RP_ID="https://example.com",
            PASSKEY_ORIGINS=["https://example.com"],
        )


def test_passkey_origin_without_scheme_fails_at_config():
    with pytest.raises(ValueError, match="must be a full origin"):
        FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            PASSKEY_ENABLED=True,
            PASSKEY_RP_ID="example.com",
            PASSKEY_ORIGINS=["example.com"],
        )


def test_passkey_redis_backend_without_url_fails_at_config():
    with pytest.raises(ValueError, match="REDIS_URL must be set"):
        FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            PASSKEY_ENABLED=True,
            PASSKEY_RP_ID="example.com",
            PASSKEY_ORIGINS=["https://example.com"],
            PASSKEY_CHALLENGE_BACKEND="redis",
        )


def test_passkey_config_happy_path():
    cfg = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        PASSKEY_ENABLED=True,
        PASSKEY_RP_ID="example.com",
        PASSKEY_ORIGINS=["https://example.com", "https://m.example.com"],
    )
    assert cfg.PASSKEY_ENABLED is True
