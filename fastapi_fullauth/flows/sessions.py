from fastapi_fullauth.adapters.base import AbstractUserAdapter, SessionAdapterMixin
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.types import SessionInfo, UserID


async def list_sessions(
    adapter: SessionAdapterMixin,
    user_id: UserID,
    *,
    current_family_id: str | None = None,
) -> list[SessionInfo]:
    """List the user's active sessions, flagging the caller's current one."""
    sessions = await adapter.list_user_sessions(user_id)
    for s in sessions:
        s.current = current_family_id is not None and s.family_id == current_family_id
    return sessions


async def revoke_session(
    adapter: SessionAdapterMixin,
    user_id: UserID,
    family_id: str,
    *,
    token_engine: TokenEngine | None = None,
) -> bool:
    """Revoke a single session. Returns False when the user does not own it.

    Pass ``token_engine`` to also invalidate the access tokens the session has
    already issued; otherwise they stay valid until they expire.
    """
    revoked = await adapter.revoke_user_session(user_id, family_id)
    if revoked and token_engine is not None:
        await token_engine.revoke_family(family_id)
    return revoked


async def revoke_other_sessions(
    adapter: SessionAdapterMixin,
    user_id: UserID,
    current_family_id: str,
    *,
    token_engine: TokenEngine | None = None,
) -> int:
    """Revoke every session except the caller's current one.

    Pass ``token_engine`` to also invalidate the access tokens those sessions
    have already issued.
    """
    if token_engine is not None:
        await revoke_user_session_tokens(
            adapter, token_engine, user_id, keep_family_id=current_family_id
        )
    return await adapter.revoke_user_sessions_except(user_id, current_family_id)


async def revoke_user_session_tokens(
    adapter: AbstractUserAdapter | SessionAdapterMixin,
    token_engine: TokenEngine,
    user_id: UserID,
    *,
    keep_family_id: str | None = None,
) -> None:
    """Invalidate the access tokens of the user's live sessions.

    Call this before revoking the sessions in storage: only live sessions are
    listed. Adapters without ``SessionAdapterMixin`` cannot enumerate sessions,
    so their already-issued access tokens stay valid until they expire.
    """
    if not isinstance(adapter, SessionAdapterMixin):
        return
    for session in await adapter.list_user_sessions(user_id):
        if session.family_id != keep_family_id:
            await token_engine.revoke_family(session.family_id)
