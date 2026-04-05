from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema


async def register(
    adapter: AbstractUserAdapter,
    data: CreateUserSchema,
) -> UserSchema:
    existing = await adapter.get_user_by_email(data.email)
    if existing is not None:
        raise UserAlreadyExistsError(f"User with email {data.email} already exists")

    hashed = hash_password(data.password)
    user = await adapter.create_user(data, hashed_password=hashed)
    return user
