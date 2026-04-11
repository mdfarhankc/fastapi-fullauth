from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_fullauth.types import UserSchema

from .config import session_maker
from .models import User


async def send_verification_email(email: str, token: str):
    print(f"\n[VERIFY] To: {email}\n[VERIFY] Token: {token}\n")


async def send_password_reset_email(email: str, token: str):
    print(f"\n[RESET] To: {email}\n[RESET] Token: {token}\n")


async def add_custom_claims(user: UserSchema) -> dict:
    return {"display_name": getattr(user, "display_name", "")}


fullauth = FullAuth(
    secret_key="change-me-use-a-32-byte-key-here",
    adapter=SQLAlchemyAdapter(session_maker=session_maker, user_model=User),
    on_create_token_claims=add_custom_claims,
    include_user_in_login=True,
)
fullauth.hooks.on("send_verification_email", send_verification_email)
fullauth.hooks.on("send_password_reset_email", send_password_reset_email)
