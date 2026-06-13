import logging
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, Depends, HTTPException, Response

from fastapi_fullauth.adapters.base import SessionAdapterMixin
from fastapi_fullauth.dependencies.current_user import CurrentUser, _extract_token, get_fullauth
from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION, TokenError
from fastapi_fullauth.flows.sessions import list_sessions, revoke_other_sessions, revoke_session
from fastapi_fullauth.routers._schemas import MessageResponse
from fastapi_fullauth.types import SessionInfo

logger = logging.getLogger("fastapi_fullauth.routers.sessions")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_sessions_router() -> APIRouter:
    router = APIRouter()

    async def _current_family_id(fullauth: "FullAuth", token: str) -> str | None:
        try:
            payload = await fullauth.token_engine.decode_token(token, expected_type="access")
        except TokenError:
            return None
        return payload.family_id

    @router.get(
        "/sessions",
        status_code=200,
        response_model=list[SessionInfo],
        description="List your active sessions. The session you're using is flagged current.",
    )
    async def list_sessions_route(
        user: CurrentUser,
        token: str = Depends(_extract_token),
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> list[SessionInfo]:
        adapter = cast("SessionAdapterMixin", fullauth.adapter)
        family_id = await _current_family_id(fullauth, token)
        return await list_sessions(adapter, user.id, current_family_id=family_id)

    @router.delete(
        "/sessions/{family_id}",
        status_code=204,
        description="Revoke one session by its family_id. Sign out that device.",
    )
    async def revoke_session_route(
        family_id: str,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> Response:
        adapter = cast("SessionAdapterMixin", fullauth.adapter)
        if not await revoke_session(adapter, user.id, family_id):
            raise HTTPException(status_code=404, detail="Session not found")
        logger.info("Session revoked: user_id=%s family_id=%s", user.id, family_id)
        return Response(status_code=204)

    @router.post(
        "/sessions/revoke-others",
        status_code=200,
        response_model=MessageResponse,
        description="Sign out everywhere except the session you're currently using.",
    )
    async def revoke_other_sessions_route(
        user: CurrentUser,
        token: str = Depends(_extract_token),
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        family_id = await _current_family_id(fullauth, token)
        if family_id is None:
            # Without the current family we can't tell which session to keep;
            # refusing avoids signing the caller out of their own session too.
            raise CREDENTIALS_EXCEPTION
        adapter = cast("SessionAdapterMixin", fullauth.adapter)
        count = await revoke_other_sessions(adapter, user.id, family_id)
        logger.info("Other sessions revoked: user_id=%s count=%s", user.id, count)
        return MessageResponse(detail=f"Signed out {count} other session(s).")

    return router
