import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig, PasswordValidator
from fastapi_fullauth.adapters.memory import InMemoryAdapter

# --- Event Hooks ---


@pytest.fixture
def hook_log():
    return []


@pytest.fixture
def hooks_app(hook_log):
    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(config=config, adapter=adapter)

    async def on_register(user):
        hook_log.append(("register", user.email))

    async def on_login(user):
        hook_log.append(("login", user.email))

    async def on_logout(user_id):
        hook_log.append(("logout", user_id))

    fullauth.hooks.on("after_register", on_register)
    fullauth.hooks.on("after_login", on_login)
    fullauth.hooks.on("after_logout", on_logout)

    app = FastAPI()
    fullauth.init_app(app)
    return app


@pytest.fixture
async def hooks_client(hooks_app):
    transport = ASGITransport(app=hooks_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_hooks_fire_on_register(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    assert ("register", "hook@test.com") in hook_log


@pytest.mark.asyncio
async def test_hooks_fire_on_login(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    await hooks_client.post(
        "/api/v1/auth/login",
        data={"username": "hook@test.com", "password": "securepass123"},
    )
    assert ("login", "hook@test.com") in hook_log


@pytest.mark.asyncio
async def test_hooks_fire_on_logout(hooks_client, hook_log):
    await hooks_client.post(
        "/api/v1/auth/register",
        json={"email": "hook@test.com", "password": "securepass123"},
    )
    r = await hooks_client.post(
        "/api/v1/auth/login",
        data={"username": "hook@test.com", "password": "securepass123"},
    )
    token = r.json()["access_token"]
    await hooks_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert any(event == "logout" for event, _ in hook_log)


# --- Password Validator ---


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
    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        password_validator=PasswordValidator(
            min_length=8, require_uppercase=True, require_digit=True
        ),
    )
    app = FastAPI()
    fullauth.init_app(app)

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


# --- Disable Routes ---


@pytest.mark.asyncio
async def test_disabled_register_route():
    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        enabled_routes=["login", "logout", "refresh"],
    )
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "securepass123"},
        )
        assert r.status_code == 404


# --- Password Reset Email Callback ---


@pytest.mark.asyncio
async def test_password_reset_email_callback():
    sent = []

    async def on_reset_email(email: str, token: str):
        sent.append({"email": email, "token": token})

    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        on_send_password_reset_email=on_reset_email,
    )
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # register a user first
        await client.post(
            "/api/v1/auth/register",
            json={"email": "reset@test.com", "password": "securepass123"},
        )

        # request reset
        r = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "reset@test.com"},
        )
        assert r.status_code == 202
        assert len(sent) == 1
        assert sent[0]["email"] == "reset@test.com"
        assert sent[0]["token"]  # token should be non-empty


# --- Login Response With User ---


@pytest.mark.asyncio
async def test_login_includes_user():
    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        include_user_in_login=True,
    )
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "user@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            data={"username": "user@test.com", "password": "securepass123"},
        )
        data = r.json()
        assert "access_token" in data
        assert "user" in data
        assert data["user"]["email"] == "user@test.com"


@pytest.mark.asyncio
async def test_login_excludes_user_by_default(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "user@test.com", "password": "securepass123"},
    )
    data = r.json()
    assert "access_token" in data
    assert "user" not in data


# --- Custom CreateUserSchema ---


@pytest.mark.asyncio
async def test_custom_create_user_schema():
    from fastapi_fullauth.types import CreateUserSchema, UserSchema

    class MyCreateSchema(CreateUserSchema):
        display_name: str

    class MyUserSchema(UserSchema):
        display_name: str | None = None

    adapter = InMemoryAdapter(user_schema=MyUserSchema)
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        create_user_schema=MyCreateSchema,
    )
    app = FastAPI()
    fullauth.init_app(app)

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


@pytest.mark.asyncio
async def test_custom_schema_rejects_missing_field():
    from fastapi_fullauth.types import CreateUserSchema

    class MyCreateSchema(CreateUserSchema):
        display_name: str

    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        create_user_schema=MyCreateSchema,
    )
    app = FastAPI()
    fullauth.init_app(app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # missing display_name should fail
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "test@test.com", "password": "securepass123"},
        )
        assert r.status_code == 422


# --- Custom Token Claims ---


@pytest.mark.asyncio
async def test_custom_token_claims():

    async def add_claims(user):
        return {"org_id": "org-123", "plan": "pro"}

    adapter = InMemoryAdapter()
    config = FullAuthConfig(SECRET_KEY="test-secret-key-that-is-long-enough-32b")
    fullauth = FullAuth(
        config=config,
        adapter=adapter,
        on_create_token_claims=add_claims,
    )
    app = FastAPI()
    fullauth.init_app(app)

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
            data={"username": "claims@test.com", "password": "securepass123"},
        )
        token = r.json()["access_token"]

        r = await client.get("/claims", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["org_id"] == "org-123"
        assert data["plan"] == "pro"
