"""
In-memory example — showcases all FullAuth features without a database.
Good for testing and prototyping.

Run: uv run uvicorn examples.memory_app:app --reload
Docs: http://localhost:8000/docs
"""

from fastapi import Depends, FastAPI

from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import (
    current_active_verified_user,
    current_user,
    require_role,
)
from fastapi_fullauth.types import CreateUserSchema, UserSchema

# --- Custom registration schema with extra fields ---


class MyCreateUserSchema(CreateUserSchema):
    display_name: str


# --- Email callbacks (replace with real email sending) ---


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

app = FastAPI(title="FullAuth In-Memory Demo")

fullauth = FullAuth(
    secret_key="change-me-use-a-32-byte-key-here",
    adapter=InMemoryAdapter(),
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
