import secrets

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema


async def create_superuser(
    adapter: AbstractUserAdapter,
    email: str,
    password: str,
) -> UserSchema:
    if await adapter.get_user_by_email(email) is not None:
        raise UserAlreadyExistsError(f"User with email {email} already exists")

    data = CreateUserSchema(email=email, password=password)
    user = await adapter.create_user(data, hashed_password=hash_password(password))
    return await adapter.update_user(str(user.id), {"is_superuser": True, "is_verified": True})


def generate_secret_key(length: int = 64) -> str:
    return secrets.token_urlsafe(length)
