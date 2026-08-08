import secrets
from typing import Literal

from starlette.requests import Request

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import ahash_password
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
    hashed = await ahash_password(password, algorithm=hash_algorithm)
    user = await adapter.create_user(data, hashed_password=hashed)
    return await adapter.update_user(user.id, {"is_superuser": True, "is_verified": True})


def generate_secret_key(length: int = 64) -> str:
    return secrets.token_urlsafe(length)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def request_session_metadata(
    request: Request,
    trusted_headers: list[str] | None = None,
    trusted_proxy_count: int = 1,
) -> tuple[str | None, str | None]:
    """Return ``(user_agent, ip_address)`` for tagging a refresh token / session.

    Both values are clamped to the storage column widths (user_agent 512,
    ip_address 45). The User-Agent header is client-controlled and effectively
    unbounded, so an oversized value would otherwise overflow the column and
    error the INSERT on strict databases (Postgres/MySQL) during login/refresh.
    """
    user_agent = request.headers.get("user-agent")
    ip_address = get_client_ip(request, trusted_headers, trusted_proxy_count)
    return (
        user_agent[:512] if user_agent else user_agent,
        ip_address[:45] if ip_address else ip_address,
    )


def get_client_ip(
    request: Request,
    trusted_headers: list[str] | None = None,
    trusted_proxy_count: int = 1,
) -> str:
    """Extract the real client IP from a trusted proxy header.

    Only headers explicitly listed in ``trusted_headers`` are consulted. For a
    comma-separated chain such as ``X-Forwarded-For``, only the right-most
    entries are trustworthy: each trusted proxy in front of the app appends the
    address it received from, so the entry ``trusted_proxy_count`` positions
    from the right is the real client. Left-most entries are client-supplied and
    spoofable, so they are never trusted. When the chain is shorter than the
    configured proxy count (a misconfiguration or an overwriting proxy), the
    direct peer is used rather than an attacker-controllable value.
    """
    hops = trusted_proxy_count if trusted_proxy_count >= 1 else 1
    for header in trusted_headers or []:
        value = request.headers.get(header)
        if not value:
            continue
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) >= hops:
            return parts[-hops]
        break
    return request.client.host if request.client else "unknown"
