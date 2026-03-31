"""
In-memory example — showcases all FullAuth features without a database.
Good for testing and prototyping.

Run: uv run uvicorn examples.memory_app:app --reload
Docs: http://localhost:8000/docs
"""

from fastapi import Depends, FastAPI

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import (
    current_active_verified_user,
    current_user,
    require_role,
)
from fastapi_fullauth.middleware import SecurityHeadersMiddleware
from fastapi_fullauth.protection.ratelimit import RateLimitMiddleware
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

# middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

fullauth = FullAuth(
    config=FullAuthConfig(
        SECRET_KEY="change-me-use-a-32-byte-key-here",
        API_PREFIX="/api/v1",
        ROUTER_TAGS=["Auth"],
    ),
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
