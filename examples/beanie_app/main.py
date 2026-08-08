"""
Run: uv run uvicorn examples.beanie_app.main:app --reload
Requires: uv add fastapi-fullauth[beanie]
Needs a running MongoDB (no replica set required); set the URI in config.py.
"""

from contextlib import asynccontextmanager

from beanie import init_beanie
from fastapi import FastAPI
from pymongo import AsyncMongoClient

from fastapi_fullauth.middleware import SecurityHeadersMiddleware

from .auth import fullauth
from .config import DATABASE_NAME, MONGO_URL
from .models import DOCUMENT_MODELS
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(MONGO_URL)
    await init_beanie(database=client[DATABASE_NAME], document_models=DOCUMENT_MODELS)
    yield
    # init_app() wraps this lifespan to run fullauth.aclose() on shutdown, so
    # only the Mongo client teardown is needed here.
    await client.close()


app = FastAPI(title="FullAuth Beanie Demo", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
fullauth.init_app(app)
app.include_router(router)
