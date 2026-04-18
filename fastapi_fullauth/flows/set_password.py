"""Set password for users who don't have a usable password (e.g. OAuth-only)."""

import logging

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import AuthenticationError
from fastapi_fullauth.types import UserID
from fastapi_fullauth.validators import PasswordValidator

logger = logging.getLogger("fastapi_fullauth.set_password")


async def set_password(
    adapter: AbstractUserAdapter,
    user_id: UserID,
    new_password: str,
    hash_algorithm: str = "argon2id",
    password_validator: PasswordValidator | None = None,
) -> None:
    """Set a password for a user who doesn't have a usable one.

    Raises AuthenticationError if the user already has a usable password
    (they should use change_password instead).
    """
    user = await adapter.get_user_by_id(user_id)
    if user is None:
        raise AuthenticationError("User not found")

    if getattr(user, "has_usable_password", True):
        raise AuthenticationError("Use change-password to update your password")

    if password_validator:
        password_validator.validate(new_password)

    new_hash = hash_password(new_password, algorithm=hash_algorithm)
    await adapter.set_password(user_id, new_hash)
    await adapter.update_user(user_id, {"has_usable_password": True})
    logger.info("Password set: user_id=%s", user_id)
