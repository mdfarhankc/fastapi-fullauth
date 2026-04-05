"""
In-memory example — no database needed.

Run: uv run uvicorn examples.memory_app:app --reload
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


class MyCreateUserSchema(CreateUserSchema):
    display_name: str


# replace these with real email sending in production
async def send_verification_email(email: str, token: str):
    print(f"\n[VERIFY] To: {email}\n[VERIFY] Token: {token}\n")


async def send_password_reset_email(email: str, token: str):
    print(f"\n[RESET] To: {email}\n[RESET] Token: {token}\n")


async def add_custom_claims(user: UserSchema) -> dict:
    return {"display_name": getattr(user, "display_name", "")}


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


@app.get("/api/v1/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/api/v1/verified-only")
async def verified_only(user=Depends(current_active_verified_user)):
    return {"msg": "your email is verified", "user": user}


@app.get("/api/v1/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "welcome admin", "user": user}
