
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import current_user


@pytest.fixture
def sent_emails():
    return []


@pytest.fixture
def verify_app(sent_emails):
    async def mock_send(email: str, token: str):
        sent_emails.append({"email": email, "token": token})

    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        on_send_verification_email=mock_send,
    )
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return user

    return app


@pytest.fixture
async def verify_client(verify_app):
    transport = ASGITransport(app=verify_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _register_and_login(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "verify@test.com", "password": "securepass123"},
    )
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "verify@test.com", "password": "securepass123"},
    )
    return r.json()


@pytest.mark.asyncio
async def test_verify_email_full_flow(verify_client, sent_emails):
    tokens = await _register_and_login(verify_client)
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
    tokens = await _register_and_login(verify_client)
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
