"""
Run: uv run uvicorn examples.sqlalchemy_app.main:app --reload
Requires: uv add fastapi-fullauth[sqlalchemy] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .auth import fullauth
from .config import engine
from .models import FullAuthBase
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(FullAuthBase.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth SQLAlchemy Demo", lifespan=lifespan)
fullauth.init_app(app)
app.include_router(router)
