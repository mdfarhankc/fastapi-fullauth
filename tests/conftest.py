import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import Field, Relationship, SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import (
    RefreshTokenRecord,
    Role,
    SQLModelAdapter,
    UserBase,
    UserRoleLink,
)
from fastapi_fullauth.dependencies import current_user


class User(UserBase, table=True):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    display_name: str = Field(default="", max_length=100)
    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship(
        cascade_delete=True,
    )


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield session_maker
    await engine.dispose()


@pytest.fixture
def config():
    return FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        INJECT_SECURITY_HEADERS=False,
    )


@pytest.fixture
def adapter(db):
    return SQLModelAdapter(session_maker=db, user_model=User)


@pytest.fixture
def fullauth(config, adapter):
    return FullAuth(config=config, adapter=adapter)


@pytest.fixture
def app(fullauth):
    app = FastAPI()
    fullauth.init_app(app, auto_middleware=False)

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
        json={"email": "user@test.com", "password": "securepass123"},
    )
    tokens = r.json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
async def login_tokens(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    return r.json()
