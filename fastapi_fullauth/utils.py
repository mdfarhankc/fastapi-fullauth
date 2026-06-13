import secrets
from typing import Literal

from starlette.requests import Request

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import CreateUserSchema, UserSchema


async def create_superuser(
    adapter: AbstractUserAdapter,
    email: str,
    password: str,
    hash_algorithm: Literal["argon2id", "bcrypt"] = "argon2id",
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


def request_session_metadata(
    request: Request, trusted_headers: list[str] | None = None
) -> tuple[str | None, str | None]:
    """Return ``(user_agent, ip_address)`` for tagging a refresh token / session.

    Both values are clamped to the storage column widths (user_agent 512,
    ip_address 45). The User-Agent header is client-controlled and effectively
    unbounded, so an oversized value would otherwise overflow the column and
    error the INSERT on strict databases (Postgres/MySQL) during login/refresh.
    """
    user_agent = request.headers.get("user-agent")
    ip_address = get_client_ip(request, trusted_headers)
    return (
        user_agent[:512] if user_agent else user_agent,
        ip_address[:45] if ip_address else ip_address,
    )


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
