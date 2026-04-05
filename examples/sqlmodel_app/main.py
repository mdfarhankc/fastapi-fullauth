"""
Run: uv run uvicorn examples.sqlmodel_app.main:app --reload
Requires: uv add fastapi-fullauth[sqlmodel] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlmodel import SQLModel

from .auth import fullauth
from .config import engine
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth SQLModel Demo", lifespan=lifespan)
fullauth.init_app(app)
app.include_router(router)
