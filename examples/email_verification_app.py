from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlalchemy import FullAuthBase, SQLAlchemyAdapter
from fastapi_fullauth.dependencies import current_active_verified_user, current_user

DATABASE_URL = "sqlite+aiosqlite:///fullauth_verify_demo.db"

engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def send_verification_email(email: str, token: str):
    """Replace this with your actual email sending logic (fastapi-mail, SMTP, etc.)."""
    print("\n--- Verification Email ---")
    print(f"To: {email}")
    print(f"Token: {token}")
    print("Link: http://localhost:8000/auth/verify-email/confirm (POST with token)")
    print("--------------------------\n")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(FullAuthBase.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth Email Verification Demo", lifespan=lifespan)

fullauth = FullAuth(
    config=FullAuthConfig(SECRET_KEY="change-me-use-a-32-byte-key-here"),
    adapter=SQLAlchemyAdapter(session_maker=session_maker),
    on_send_verification_email=send_verification_email,
)
fullauth.init_app(app)


@app.get("/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/verified-only")
async def verified_only(user=Depends(current_active_verified_user)):
    """This endpoint requires a verified email."""
    return {"msg": "your email is verified", "user": user}
