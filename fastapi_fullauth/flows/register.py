import logging

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema

logger = logging.getLogger("fastapi_fullauth.register")


async def register(
    adapter: AbstractUserAdapter,
    data: CreateUserSchema,
    login_field: str = "email",
    hash_algorithm: str = "argon2id",
) -> UserSchema:
    existing = await adapter.get_user_by_email(data.email)
    if existing is not None:
        logger.warning("Registration rejected — email exists: %s", data.email)
        raise UserAlreadyExistsError(f"User with email {data.email} already exists")

    if login_field != "email":
        login_value = getattr(data, login_field, None)
        if login_value is not None:
            existing = await adapter.get_user_by_field(login_field, login_value)
            if existing is not None:
                logger.warning("Registration rejected — %s exists", login_field)
                raise UserAlreadyExistsError(f"User with {login_field} already exists")

    hashed = hash_password(data.password, algorithm=hash_algorithm)
    user = await adapter.create_user(data, hashed_password=hashed)
    logger.info("User registered: user_id=%s, email=%s", user.id, user.email)
    return user
