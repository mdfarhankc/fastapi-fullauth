from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import hash_password, password_needs_rehash, verify_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import AccountLockedError, AuthenticationError
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.types import RefreshToken, TokenPair, UserSchema


async def login(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    identifier: str,
    password: str,
    login_field: str = "email",
    lockout: LockoutManager | None = None,
    extra_claims: dict | None = None,
    user: UserSchema | None = None,
) -> TokenPair:
    if lockout and lockout.is_locked(identifier):
        raise AccountLockedError(f"Account {identifier} is temporarily locked")

    if user is None:
        user = await adapter.get_user_by_field(login_field, identifier)
    if user is None:
        if lockout:
            lockout.record_failure(identifier)
        raise AuthenticationError("Invalid credentials")

    hashed = await adapter.get_hashed_password(str(user.id))
    if hashed is None or not verify_password(password, hashed):
        if lockout:
            lockout.record_failure(identifier)
        raise AuthenticationError("Invalid credentials")

    if not user.is_active:
        raise AuthenticationError("User account is deactivated")

    if password_needs_rehash(hashed):
        await adapter.set_password(str(user.id), hash_password(password))

    if lockout:
        lockout.clear(identifier)

    roles = await adapter.get_user_roles(str(user.id))
    access, refresh_meta = token_engine.create_token_pair(
        user_id=str(user.id),
        roles=roles,
        extra=extra_claims,
    )

    await adapter.store_refresh_token(
        RefreshToken(
            token=refresh_meta.token,
            user_id=str(user.id),
            expires_at=refresh_meta.expires_at,
            family_id=refresh_meta.family_id,
        )
    )

    return TokenPair(
        access_token=access,
        refresh_token=refresh_meta.token,
        expires_in=token_engine.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
