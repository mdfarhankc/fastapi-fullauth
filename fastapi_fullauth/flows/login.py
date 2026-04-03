
from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.core.crypto import verify_password
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.exceptions import AccountLockedError, AuthenticationError
from fastapi_fullauth.protection.lockout import LockoutManager
from fastapi_fullauth.types import RefreshToken, TokenPair


async def login(
    adapter: AbstractUserAdapter,
    token_engine: TokenEngine,
    email: str,
    password: str,
    lockout: LockoutManager | None = None,
    extra_claims: dict | None = None,
) -> TokenPair:
    if lockout and lockout.is_locked(email):
        raise AccountLockedError(f"Account {email} is temporarily locked")

    user = await adapter.get_user_by_email(email)
    if user is None:
        if lockout:
            lockout.record_failure(email)
        raise AuthenticationError("Invalid email or password")

    hashed = await adapter.get_hashed_password(str(user.id))
    if hashed is None or not verify_password(password, hashed):
        if lockout:
            lockout.record_failure(email)
        raise AuthenticationError("Invalid email or password")

    if not user.is_active:
        raise AuthenticationError("User account is deactivated")

    if lockout:
        lockout.clear(email)

    roles = await adapter.get_user_roles(str(user.id))
    access, refresh = token_engine.create_token_pair(
        user_id=str(user.id),
        roles=roles,
        extra=extra_claims,
    )

    # persist refresh token in DB for revocation / reuse detection
    refresh_payload = await token_engine.decode_token(refresh)
    await adapter.store_refresh_token(RefreshToken(
        token=refresh,
        user_id=str(user.id),
        expires_at=refresh_payload.exp,
        family_id=refresh_payload.family_id,
    ))

    return TokenPair(access_token=access, refresh_token=refresh)
