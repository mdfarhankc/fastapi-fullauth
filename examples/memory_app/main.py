"""
Run: uv run uvicorn examples.memory_app.main:app --reload
No database needed — everything in memory.
"""

from fastapi import FastAPI

from .auth import fullauth
from .routes import router

app = FastAPI(title="FullAuth Memory Demo")
fullauth.init_app(app)
app.include_router(router)
