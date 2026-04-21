# Testing apps that use fastapi-fullauth

Patterns for writing fast, isolated tests against code that depends on this library. Built around `pytest-asyncio`, an in-memory SQLite database, and `httpx.AsyncClient` over `ASGITransport`.

## Minimal fixture stack

```python
# conftest.py
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

from myapp.models import User


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def adapter(db):
    return SQLModelAdapter(session_maker=db, user_model=User)


@pytest.fixture
def fullauth(adapter):
    return FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="test-secret-key-that-is-long-enough-32b",
            INJECT_SECURITY_HEADERS=False,
            AUTH_RATE_LIMIT_ENABLED=False,
        ),
        adapter=adapter,
    )


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)
    return app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
```

Key choices:

- **`sqlite+aiosqlite://`** (no path) gives a per-process in-memory DB that dies with the fixture. Zero cleanup needed.
- **`expire_on_commit=False`** prevents lazy-loads after commit — async code can't do them.
- **`AUTH_RATE_LIMIT_ENABLED=False`** in tests so hammering the login endpoint doesn't hit `429 Too Many Requests` on the 6th attempt.
- **`auto_middleware=False`** in `init_app` skips CSRF / security headers / rate limit middleware — tests usually want to assert on the raw route behavior without middleware in the way.

## Registered-user and authenticated-headers helpers

```python
@pytest.fixture
async def registered_user(client):
    await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "testpass123"},
    )


@pytest.fixture
async def auth_headers(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "testpass123"},
    )
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
```

Use `auth_headers` for any test that needs an authenticated request.

## Mocking email hooks

The library doesn't send emails — it emits hooks. Tests should register an in-memory collector:

```python
@pytest.fixture
async def sent_emails():
    return []


@pytest.fixture
def fullauth(adapter, sent_emails):
    fa = FullAuth(config=..., adapter=adapter)

    async def capture(user, token):
        sent_emails.append({"type": "verify", "to": user.email, "token": token})

    fa.hooks.on("send_email_verification", capture)
    fa.hooks.on(
        "send_password_reset",
        lambda user, token: sent_emails.append(
            {"type": "reset", "to": user.email, "token": token}
        ),
    )
    return fa
```

Then assertions read from `sent_emails`:

```python
async def test_password_reset_sends_email(client, registered_user, sent_emails):
    await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "user@test.com"},
    )
    assert sent_emails[-1]["type"] == "reset"
    assert sent_emails[-1]["to"] == "user@test.com"
```

## Forging an access token directly

Going through `/login` on every test is slow. For tests that just need "user X is authenticated," mint a token from the token engine:

```python
@pytest.fixture
async def token_for(fullauth):
    async def _make(user):
        roles = await fullauth.adapter.get_user_roles(user.id)
        access, _ = fullauth.token_engine.create_token_pair(user_id=str(user.id), roles=roles)
        return access
    return _make
```

Usage:

```python
async def test_something(client, token_for, adapter):
    user = await adapter.create_user(CreateUserSchema(...), hashed_password=...)
    token = await token_for(user)
    r = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
```

## Testing opt-in anti-enumeration

The default for `PREVENT_REGISTRATION_ENUMERATION` is `False`. Flip it in a local config to test the anti-enum path:

```python
async def test_register_hides_existence():
    fullauth = FullAuth(
        config=FullAuthConfig(
            SECRET_KEY="...",
            PREVENT_REGISTRATION_ENUMERATION=True,
        ),
        adapter=adapter,
    )
    # ... wire up app + client ...
    new = await client.post("/api/v1/auth/register", json={"email": "x@y.com", "password": "..."})
    dup = await client.post("/api/v1/auth/register", json={"email": "x@y.com", "password": "..."})
    assert new.status_code == 202
    assert dup.status_code == 202
    assert new.json() == dup.json()
```

## Testing lockout

Default `MAX_LOGIN_ATTEMPTS=5`. Combined with the default `AUTH_RATE_LIMIT_LOGIN=5`, a test that tries 6 wrong passwords will hit the rate limiter first. Two fixes:

- Disable the rate limiter (`AUTH_RATE_LIMIT_ENABLED=False`) — usual choice in tests.
- Lower the lockout threshold (`MAX_LOGIN_ATTEMPTS=2`) to hit lockout faster than the rate limit.

```python
fullauth = FullAuth(
    config=FullAuthConfig(
        ...,
        MAX_LOGIN_ATTEMPTS=2,
        AUTH_RATE_LIMIT_ENABLED=False,
    ),
    adapter=adapter,
)
```

## Testing passkeys

The WebAuthn verification requires a valid signed credential from a real authenticator — you can't easily fake it with plain `httpx`. Two realistic approaches:

1. **Adapter-level tests.** Mock the `webauthn` library calls with `unittest.mock.patch` and assert the adapter wires everything correctly (challenge store, sign-count CAS, userHandle check).
2. **Playwright integration tests.** Use Chromium's virtual authenticator API to produce real assertions. The library's own test suite in `tests/test_passkey.py` covers challenge store + adapter CAS, not end-to-end browser flow — same approach works in your app.

## Testing OAuth

Use a `MockOAuthProvider` that returns a canned `OAuthUserInfo` from `get_user_info`:

```python
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo


class MockOAuthProvider(OAuthProvider):
    name = "mock"

    def __init__(self, user_info: OAuthUserInfo):
        self.client_id = "test"
        self.client_secret = "test"
        self.redirect_uris = ["http://localhost/cb"]
        self._user_info = user_info

    @property
    def default_scopes(self):
        return ["email"]

    def get_authorization_url(self, state, redirect_uri):
        return f"https://mock/auth?state={state}"

    async def exchange_code(self, code, redirect_uri):
        return {"access_token": "fake-token"}

    async def get_user_info(self, tokens):
        return self._user_info
```

Drive it through `fullauth.oauth_callback` or the router. Change `email_verified` / email to exercise the auto-link / anti-takeover paths.

## Gotchas

- **Clock-sensitive tests** (token expiry, OAuth state expiry) need `JWT_LEEWAY_SECONDS=0` in the config — the default 30-second leeway makes "expires in 1 second, sleep 1.1s, assert rejected" fail.
- **Warnings in pytest output:** the library emits a `UserWarning` when any backend is `"memory"` and the matching feature is enabled. `pyproject.toml` has a `filterwarnings = ["ignore:In-memory backends in use:UserWarning"]` entry that silences it in-tree — add the same to your app's `pyproject.toml` if you don't want that noise.
- **Each test gets a fresh DB.** Don't share users across tests — the fixture-scoped engine is per-function.
