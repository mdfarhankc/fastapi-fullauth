"""
SQLModel example with custom user fields.

Run: uv run uvicorn examples.sqlmodel_app:app --reload
Requires: uv add fastapi-fullauth[sqlmodel] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import Field, Relationship, SQLModel

from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.sqlmodel import (
    RefreshTokenRecord,
    Role,
    SQLModelAdapter,
    UserBase,
    UserRoleLink,
)
from fastapi_fullauth.dependencies import (
    current_active_verified_user,
    current_user,
    require_role,
)
from fastapi_fullauth.types import UserSchema

DATABASE_URL = "sqlite+aiosqlite:///fullauth_sqlmodel_demo.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


class MyUser(UserBase, table=True):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    # need to re-declare these when subclassing UserBase
    roles: list[Role] = Relationship(back_populates="users", link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship(back_populates="user")


async def send_verification_email(email: str, token: str):
    print(f"\n[VERIFY] To: {email}\n[VERIFY] Token: {token}\n")


async def send_password_reset_email(email: str, token: str):
    print(f"\n[RESET] To: {email}\n[RESET] Token: {token}\n")


async def add_custom_claims(user: UserSchema) -> dict:
    return {"display_name": getattr(user, "display_name", "")}


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth SQLModel Demo", lifespan=lifespan)

fullauth = FullAuth(
    secret_key="change-me-use-a-32-byte-key-here",
    adapter=SQLModelAdapter(session_maker=session_maker, user_model=MyUser),
    on_send_verification_email=send_verification_email,
    on_send_password_reset_email=send_password_reset_email,
    on_create_token_claims=add_custom_claims,
    include_user_in_login=True,
)
fullauth.init_app(app)


@app.get("/api/v1/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/api/v1/verified-only")
async def verified_only(user=Depends(current_active_verified_user)):
    return {"msg": "your email is verified", "user": user}


@app.get("/api/v1/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "welcome admin", "user": user}
