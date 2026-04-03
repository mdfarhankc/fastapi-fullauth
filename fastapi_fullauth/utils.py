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
    """Create a superuser. Raises UserAlreadyExistsError if email is taken."""
    existing = await adapter.get_user_by_email(email)
    if existing is not None:
        raise UserAlreadyExistsError(f"User with email {email} already exists")

    hashed = hash_password(password)
    data = CreateUserSchema(email=email, password=password)
    user = await adapter.create_user(data, hashed_password=hashed)
    await adapter.update_user(str(user.id), {"is_superuser": True, "is_verified": True})
    updated = await adapter.get_user_by_id(str(user.id))
    return updated  # type: ignore[return-value]


def generate_secret_key(length: int = 64) -> str:
    """Generate a cryptographically secure secret key."""
    return secrets.token_urlsafe(length)
