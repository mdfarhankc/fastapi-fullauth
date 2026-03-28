from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.dependencies import current_user, require_role

DATABASE_URL = "sqlite+aiosqlite:///fullauth_sqlmodel_demo.db"

engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth + SQLModel Demo", lifespan=lifespan)

fullauth = FullAuth(
    config=FullAuthConfig(SECRET_KEY="change-me-use-a-32-byte-key-here"),
    adapter=SQLModelAdapter(session_maker=session_maker),
)
fullauth.init_app(app)


@app.get("/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "welcome admin", "user": user}
