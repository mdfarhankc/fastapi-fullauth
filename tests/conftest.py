from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import current_user


@pytest.fixture
def config():
    return FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")


@pytest.fixture
def adapter():
    return InMemoryAdapter()


@pytest.fixture
def fullauth(config, adapter):
    return FullAuth(config=config, adapter=adapter)


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app)

    @app.get("/me")
    async def me(user=Depends(current_user)):
        return user

    return app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def registered_user(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    return r.json()


@pytest.fixture
async def auth_headers(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "user@test.com", "password": "securepass123"},
    )
    tokens = r.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
async def login_tokens(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "user@test.com", "password": "securepass123"},
    )
    return r.json()
