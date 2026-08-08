from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import BeanieAdapter
from fastapi_fullauth.types import UserSchema

from .models import RefreshToken, Role, User


async def add_custom_claims(user: UserSchema) -> dict:
    return {"display_name": getattr(user, "display_name", "")}


# Beanie needs no session_maker - it uses the collections bound at init_beanie().
# Roles are embedded on the user document, so only role_model is passed (no
# user_role_model).
fullauth = FullAuth(
    adapter=BeanieAdapter(
        user_model=User,
        refresh_token_model=RefreshToken,
        role_model=Role,
    ),
    config=FullAuthConfig(
        SECRET_KEY="change-me-use-a-32-byte-key-here",
    ),
    on_create_token_claims=add_custom_claims,
)


@fullauth.hooks.on("send_verification_email")
async def send_verification_email(email: str, token: str):
    print(f"\n[VERIFY] To: {email}\n[VERIFY] Token: {token}\n")


@fullauth.hooks.on("send_password_reset_email")
async def send_password_reset_email(email: str, token: str):
    print(f"\n[RESET] To: {email}\n[RESET] Token: {token}\n")
