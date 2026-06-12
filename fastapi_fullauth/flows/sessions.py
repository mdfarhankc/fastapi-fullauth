from fastapi_fullauth.adapters.base import SessionAdapterMixin
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
) -> bool:
    """Revoke a single session. Returns False when the user does not own it."""
    return await adapter.revoke_user_session(user_id, family_id)


async def revoke_other_sessions(
    adapter: SessionAdapterMixin,
    user_id: UserID,
    current_family_id: str,
) -> int:
    """Revoke every session except the caller's current one."""
    return await adapter.revoke_user_sessions_except(user_id, current_family_id)
