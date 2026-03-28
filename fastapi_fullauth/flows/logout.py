from __future__ import annotations

from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.types import TokenPayload


async def logout(token_engine: TokenEngine, token_payload: TokenPayload) -> None:
    token_engine.blacklist_token(token_payload.jti)
