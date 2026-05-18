"""
Run: uv run uvicorn examples.sqlalchemy_app.main:app --reload
Requires: uv add fastapi-fullauth[sqlalchemy] aiosqlite
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi_fullauth.middleware import SecurityHeadersMiddleware

from .auth import fullauth
from .config import engine
from .models import Base
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FullAuth SQLAlchemy Demo", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
fullauth.init_app(app)
app.include_router(router)
