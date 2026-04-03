"""
SQLAlchemy example — full-featured FullAuth with PostgreSQL/SQLite.
Shows custom user fields with auto-derived schemas.

Run: uv run uvicorn examples.sqlalchemy_app:app --reload
Docs: http://localhost:8000/docs

Requires: uv add fastapi-fullauth[sqlalchemy] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy import String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.sqlalchemy import (
    FullAuthBase,
    SQLAlchemyAdapter,
    UserModel,
)
from fastapi_fullauth.dependencies import (
    current_active_verified_user,
    current_user,
    require_role,
)
from fastapi_fullauth.types import UserSchema

# --- Database setup ---

DATABASE_URL = "sqlite+aiosqlite:///fullauth_sqlalchemy_demo.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


# --- Custom user model (extend the built-in one) ---
# That's it — schemas are auto-derived from the model columns!


class MyUser(UserModel):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    display_name: Mapped[str] = mapped_column(String(100), nullable=True, default="")
    phone: Mapped[str] = mapped_column(String(20), nullable=True, default="")


# --- Email callbacks ---


async def send_verification_email(email: str, token: str):
    print(f"\n[VERIFY] To: {email}")
    print(f"[VERIFY] Token: {token}\n")


async def send_password_reset_email(email: str, token: str):
    print(f"\n[RESET] To: {email}")
    print(f"[RESET] Token: {token}\n")


# --- Custom token claims ---


async def add_custom_claims(user: UserSchema) -> dict:
    return {"display_name": getattr(user, "display_name", "")}


# --- App setup ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(FullAuthBase.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth SQLAlchemy Demo", lifespan=lifespan)

fullauth = FullAuth(
    secret_key="change-me-use-a-32-byte-key-here",
    adapter=SQLAlchemyAdapter(session_maker=session_maker, user_model=MyUser),
    on_send_verification_email=send_verification_email,
    on_send_password_reset_email=send_password_reset_email,
    on_create_token_claims=add_custom_claims,
    include_user_in_login=True,
)
fullauth.init_app(app)


# --- Protected routes ---


@app.get("/api/v1/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/api/v1/verified-only")
async def verified_only(user=Depends(current_active_verified_user)):
    return {"msg": "your email is verified", "user": user}


@app.get("/api/v1/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "welcome admin", "user": user}
