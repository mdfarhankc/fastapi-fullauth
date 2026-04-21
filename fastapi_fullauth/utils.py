import secrets

from starlette.requests import Request

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema


async def create_superuser(
    adapter: AbstractUserAdapter,
    email: str,
    password: str,
    hash_algorithm: str = "argon2id",
) -> UserSchema:
    if await adapter.get_user_by_email(email) is not None:
        raise UserAlreadyExistsError(f"User with email {email} already exists")

    data = CreateUserSchema(email=email, password=password)
    hashed = hash_password(password, algorithm=hash_algorithm)
    user = await adapter.create_user(data, hashed_password=hashed)
    return await adapter.update_user(user.id, {"is_superuser": True, "is_verified": True})


def generate_secret_key(length: int = 64) -> str:
    return secrets.token_urlsafe(length)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def get_client_ip(request: Request, trusted_headers: list[str] | None = None) -> str:
    """Extract the real client IP, checking trusted proxy headers first.

    Only headers explicitly listed in ``trusted_headers`` are consulted.
    When a header contains a comma-separated chain (e.g. ``X-Forwarded-For``),
    the first (left-most, i.e. original client) address is returned.
    """
    for header in trusted_headers or []:
        value = request.headers.get(header)
        if value:
            # take the first IP in the chain (original client)
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
