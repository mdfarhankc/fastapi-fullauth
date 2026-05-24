# Testing

This guide shows how to test applications built with fastapi-fullauth using pytest and httpx.

## Test setup

Create a test fixture that sets up an in-memory SQLite database, a FullAuth instance with a fixed secret key, and an httpx `AsyncClient`.

```python
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from myapp.models import User, RefreshToken  # your models
from myapp.adapter import MyAdapter           # your adapter


@pytest_asyncio.fixture
async def app():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-at-least-32-chars-long",
        ACCESS_TOKEN_EXPIRE_MINUTES=5,
        REFRESH_TOKEN_EXPIRE_DAYS=1,
    )
    adapter = MyAdapter(session_factory=session_factory)
    auth = FullAuth(adapter=adapter, config=config)

    app = FastAPI()
    auth.init_app(app)

    yield app

    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c
```

!!! tip
    Use a fixed `SECRET_KEY` in tests. The auto-generated key changes on every restart, which makes token-based tests unreliable.

## Authentication helpers

Create helper functions that register a user and return tokens:

```python
async def create_test_user(client: AsyncClient) -> dict:
    """Register a user and return the response body."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": "test@example.com",
        "password": "testpassword123",
    })
    assert resp.status_code == 201
    return resp.json()


async def login(client: AsyncClient, email: str, password: str) -> dict:
    """Log in and return the token pair."""
    resp = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": password,
    })
    assert resp.status_code == 200
    return resp.json()


def auth_header(token: str) -> dict:
    """Build an Authorization header."""
    return {"Authorization": f"Bearer {token}"}
```

## Testing protected routes

```python
@pytest.mark.asyncio
async def test_protected_route(client):
    await create_test_user(client)
    tokens = await login(client, "test@example.com", "testpassword123")

    # Authenticated request
    resp = await client.get(
        "/api/v1/auth/me",
        headers=auth_header(tokens["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"

    # Unauthenticated request
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401
```

## Testing token refresh

```python
@pytest.mark.asyncio
async def test_refresh_token(client):
    await create_test_user(client)
    tokens = await login(client, "test@example.com", "testpassword123")

    resp = await client.post("/api/v1/auth/refresh", json={
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 200

    new_tokens = resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
```

## Testing logout

```python
@pytest.mark.asyncio
async def test_logout(client):
    await create_test_user(client)
    tokens = await login(client, "test@example.com", "testpassword123")

    # Logout
    resp = await client.post(
        "/api/v1/auth/logout",
        headers=auth_header(tokens["access_token"]),
    )
    assert resp.status_code == 204

    # Old token should be rejected
    resp = await client.get(
        "/api/v1/auth/me",
        headers=auth_header(tokens["access_token"]),
    )
    assert resp.status_code == 401
```

## Testing hooks

Register a hook that collects calls, then assert it was invoked:

```python
@pytest.mark.asyncio
async def test_after_login_hook(app, client):
    fullauth = app.state.fullauth
    calls = []

    async def on_login(user):
        calls.append(user.email)

    fullauth.hooks.on("after_login", on_login)

    await create_test_user(client)
    await login(client, "test@example.com", "testpassword123")

    assert calls == ["test@example.com"]
```

## Testing roles and permissions

```python
@pytest.mark.asyncio
async def test_require_role(app, client):
    fullauth = app.state.fullauth
    await create_test_user(client)
    tokens = await login(client, "test@example.com", "testpassword123")

    # Get user ID from /me
    me = await client.get("/api/v1/auth/me", headers=auth_header(tokens["access_token"]))
    user_id = me.json()["id"]

    # Assign role (requires a superuser, so do it via adapter directly)
    await fullauth.adapter.assign_role(user_id, "editor")

    # Re-login to get updated token with roles
    tokens = await login(client, "test@example.com", "testpassword123")

    # Now test a route protected with require_role("editor")
    # (assuming you've set one up in your app)
```

!!! note
    Role changes take effect on the next login or token refresh. The roles claim is embedded in the JWT at creation time. Existing access tokens keep their old roles until they expire or are refreshed.

## Disabling rate limiting in tests

Rate limiting can interfere with tests that make many requests. Disable it in your test config:

```python
config = FullAuthConfig(
    SECRET_KEY="test-secret-key-at-least-32-chars-long",
    AUTH_RATE_LIMIT_ENABLED=False,
    LOCKOUT_ENABLED=False,
)
```

## Running the library's own tests

If you're contributing to fastapi-fullauth:

```bash
uv sync --all-extras --all-groups
uv run pytest tests/ -x -q
```

The test suite uses an in-memory SQLite database and runs entirely offline.
