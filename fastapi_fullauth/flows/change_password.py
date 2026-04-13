import logging

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password, verify_password
from fastapi_fullauth.exceptions import AuthenticationError
from fastapi_fullauth.types import UserID
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth.change_password")


async def change_password(
    adapter: AbstractUserAdapter,
    user_id: UserID,
    current_password: str,
    new_password: str,
    hash_algorithm: str = "argon2id",
    password_validator: PasswordValidator | None = None,
) -> None:
    hashed = await adapter.get_hashed_password(user_id)
    if hashed is None or not verify_password(current_password, hashed):
        logger.warning("Password change failed — wrong current password: user_id=%s", user_id)
        raise AuthenticationError("Current password is incorrect")

    if password_validator:
        password_validator.validate(new_password)

    new_hash = hash_password(new_password, algorithm=hash_algorithm)
    await adapter.set_password(user_id, new_hash)
    await adapter.revoke_all_user_refresh_tokens(user_id)
    logger.info("Password changed: user_id=%s", user_id)
