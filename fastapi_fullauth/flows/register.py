from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema


async def register(
    adapter: AbstractUserAdapter,
    data: CreateUserSchema,
    login_field: str = "email",
) -> UserSchema:
    existing = await adapter.get_user_by_email(data.email)
    if existing is not None:
        raise UserAlreadyExistsError(f"User with email {data.email} already exists")

    if login_field != "email":
        login_value = getattr(data, login_field, None)
        if login_value is not None:
            existing = await adapter.get_user_by_field(login_field, login_value)
            if existing is not None:
                raise UserAlreadyExistsError(f"User with {login_field} already exists")

    hashed = hash_password(data.password)
    user = await adapter.create_user(data, hashed_password=hashed)
    return user
