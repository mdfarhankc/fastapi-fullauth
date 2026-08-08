"""
Run: uv run uvicorn examples.tortoise_app.main:app --reload
Requires: uv add fastapi-fullauth[tortoise]
On Windows also install tzdata (Tortoise 1.x uses tz-aware datetimes).
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise import Tortoise

from fastapi_fullauth.middleware import SecurityHeadersMiddleware

from .auth import fullauth
from .config import DATABASE_URL, MODELS_MODULE
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await Tortoise.init(db_url=DATABASE_URL, modules={"models": [MODELS_MODULE]})
    await Tortoise.generate_schemas(safe=True)  # dev only; use migrations in production
    yield
    # init_app() wraps this lifespan to run fullauth.aclose() on shutdown, so
    # only the Tortoise teardown is needed here.
    await Tortoise.close_connections()


app = FastAPI(title="FullAuth Tortoise Demo", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
fullauth.init_app(app)
app.include_router(router)
