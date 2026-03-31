"""
SQLAlchemy example — full-featured FullAuth with PostgreSQL/SQLite.
Shows custom user fields, email verification, custom claims, and middleware.

Run: uv run uvicorn examples.sqlalchemy_app:app --reload
Docs: http://localhost:8000/docs

Requires: uv add fastapi-fullauth[sqlalchemy] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy import String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from fastapi_fullauth import FullAuth, FullAuthConfig
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
from fastapi_fullauth.middleware import SecurityHeadersMiddleware
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware
from fastapi_fullauth.types import CreateUserSchema, UserSchema

# --- Database setup ---

DATABASE_URL = "sqlite+aiosqlite:///fullauth_sqlalchemy_demo.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


# --- Custom user model (extend the built-in one) ---


class MyUser(UserModel):
    __tablename__ = "fullauth_users"
    __table_args__ = {"extend_existing": True}

    display_name: Mapped[str] = mapped_column(String(100), nullable=True, default="")
    phone: Mapped[str] = mapped_column(String(20), nullable=True, default="")


# --- Custom schemas ---


class MyCreateUserSchema(CreateUserSchema):
    display_name: str = ""
    phone: str = ""


class MyUserSchema(UserSchema):
    display_name: str = ""
    phone: str = ""


# --- Custom adapter to return extended schema ---


class MyAdapter(SQLAlchemyAdapter):
    def _to_schema(self, user: MyUser) -> MyUserSchema:
        return MyUserSchema(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_superuser=user.is_superuser,
            roles=[r.name for r in user.roles],
            display_name=user.display_name or "",
            phone=user.phone or "",
        )


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

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

fullauth = FullAuth(
    config=FullAuthConfig(
        SECRET_KEY="change-me-use-a-32-byte-key-here",
        API_PREFIX="/api/v1",
        ROUTER_TAGS=["Auth"],
    ),
    adapter=MyAdapter(session_maker=session_maker),
    on_send_verification_email=send_verification_email,
    on_send_password_reset_email=send_password_reset_email,
    create_user_schema=MyCreateUserSchema,
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
