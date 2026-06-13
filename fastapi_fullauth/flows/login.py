import logging
from typing import Any, Literal

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password, password_needs_rehash, verify_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import AccountLockedError, AuthenticationError
from fastapi_fullauth.flows.tokens import issue_token_pair
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.types import TokenPair, UserSchema

logger = logging.getLogger("fastapi_fullauth.login")

_DUMMY_HASH: str | None = None


def _get_dummy_hash() -> str:
    """Lazily build a valid argon2 hash so timing-defense verifies take real time."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("fastapi-fullauth-timing-defense")
    return _DUMMY_HASH


async def login(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    identifier: str,
    password: str,
    login_field: str = "email",
    lockout: LockoutManager | None = None,
    extra_claims: dict[str, Any] | None = None,
    user: UserSchema | None = None,
    hash_algorithm: Literal["argon2id", "bcrypt"] = "argon2id",
    prevent_timing_attacks: bool = False,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> TokenPair:
    if lockout and await lockout.is_locked(identifier):
        logger.warning("Login blocked; account locked: %s", identifier)
        raise AccountLockedError("Account is temporarily locked")

    if user is None:
        user = await adapter.get_user_by_field(login_field, identifier)

    hashed: str | None = None
    if user is not None:
        hashed = await adapter.get_hashed_password(user.id)

    if user is None or hashed is None:
        if prevent_timing_attacks:
            verify_password(password, _get_dummy_hash())
        if lockout:
            await lockout.record_failure(identifier)
        logger.warning("Login failed; unknown user or no password: %s", identifier)
        raise AuthenticationError("Invalid credentials")

    if not verify_password(password, hashed):
        if lockout:
            await lockout.record_failure(identifier)
        logger.warning("Login failed; invalid password: %s", identifier)
        raise AuthenticationError("Invalid credentials")

    if not user.is_active:
        logger.warning("Login failed; account deactivated: %s", identifier)
        raise AuthenticationError("User account is deactivated")

    if password_needs_rehash(hashed, algorithm=hash_algorithm):
        try:
            await adapter.set_password(user.id, hash_password(password, algorithm=hash_algorithm))
        except Exception:
            # A transient DB error here mustn't block a successful login.
            logger.exception("Password rehash failed for user_id=%s", user.id)

    if lockout:
        await lockout.clear(identifier)

    logger.info("Login successful: user_id=%s", user.id)
    return await issue_token_pair(
        adapter,
        token_engine,
        user,
        extra_claims=extra_claims,
        user_agent=user_agent,
        ip_address=ip_address,
    )
