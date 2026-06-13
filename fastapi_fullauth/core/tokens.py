import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.core.blacklist import (
    InMemoryTokenBlacklist,
    RedisTokenBlacklist,
    TokenBlacklist,
)
from fastapi_fullauth.exceptions import TokenBlacklistedError, TokenError, TokenExpiredError
from fastapi_fullauth.types import RefreshTokenMeta, TokenPayload

logger = logging.getLogger("fastapi_fullauth.tokens")


class TokenEngine:
    def __init__(self, config: FullAuthConfig, blacklist: TokenBlacklist | None = None) -> None:
        self.config = config
        self.blacklist = blacklist or InMemoryTokenBlacklist()

    def create_access_token(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict[str, Any] | None = None,
        expire_seconds: int | None = None,
        family_id: str | None = None,
    ) -> str:
        if self.config.SECRET_KEY is None:
            raise RuntimeError("SECRET_KEY must be set to create tokens")
        now = datetime.now(timezone.utc)
        if expire_seconds is not None:
            expires = now + timedelta(seconds=expire_seconds)
        else:
            expires = now + timedelta(minutes=self.config.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload: dict[str, Any] = {
            "sub": user_id,
            "exp": expires,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": "access",
            "roles": roles or [],
            "extra": extra or {},
        }
        # Carry the refresh-token family so the session list can flag the
        # device the caller is currently on. Omitted when unknown.
        if family_id is not None:
            payload["family_id"] = family_id
        return jwt.encode(payload, self.config.SECRET_KEY, algorithm=self.config.ALGORITHM)

    def create_refresh_token(
        self,
        user_id: str,
        family_id: str | None = None,
    ) -> RefreshTokenMeta:
        if self.config.SECRET_KEY is None:
            raise RuntimeError("SECRET_KEY must be set to create tokens")
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=self.config.REFRESH_TOKEN_EXPIRE_DAYS)
        resolved_family_id = family_id or uuid.uuid4().hex
        payload: dict[str, Any] = {
            "sub": user_id,
            "exp": expires_at,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": "refresh",
            "family_id": resolved_family_id,
        }
        token = jwt.encode(payload, self.config.SECRET_KEY, algorithm=self.config.ALGORITHM)
        return RefreshTokenMeta(token=token, expires_at=expires_at, family_id=resolved_family_id)

    async def decode_token(
        self,
        token: str,
        *,
        expected_type: str | None = None,
        expected_purpose: str | None = None,
    ) -> TokenPayload:
        """Decode and fully validate a token.

        Pass ``expected_type`` (e.g. ``"access"``/``"refresh"``) and/or
        ``expected_purpose`` (e.g. ``"password_reset"``) to confine the token to
        a single role at the point of use. Centralising the check here means a
        caller can't accidentally accept, say, a password-reset token where a
        session token is required.
        """
        if self.config.SECRET_KEY is None:
            raise RuntimeError("SECRET_KEY must be set to decode tokens")
        try:
            data = jwt.decode(
                token,
                self.config.SECRET_KEY,
                algorithms=[self.config.ALGORITHM],
                leeway=self.config.JWT_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Token decode failed; expired")
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.debug("Token decode failed; invalid: %s", e)
            raise TokenError(f"Invalid token: {e}")

        jti = data.get("jti", "")
        if self.config.BLACKLIST_ENABLED and await self.blacklist.is_blacklisted(jti):
            logger.warning("Blacklisted token used: jti=%s, sub=%s", jti, data.get("sub"))
            raise TokenBlacklistedError("Token has been revoked")

        if expected_type is not None and data.get("type", "access") != expected_type:
            logger.warning(
                "Token type mismatch: expected=%s got=%s", expected_type, data.get("type")
            )
            raise TokenError("Unexpected token type")

        # `extra` is a caller-set claim; a signed token whose `extra` isn't a dict
        # must be rejected cleanly rather than raising AttributeError into a 500.
        extra = data.get("extra")
        if not isinstance(extra, dict):
            extra = {}
        purpose = extra.get("purpose")
        if expected_purpose is not None and purpose != expected_purpose:
            logger.warning("Token purpose mismatch: expected=%s", expected_purpose)
            raise TokenError("Unexpected token purpose")

        return TokenPayload(
            sub=data["sub"],
            exp=datetime.fromtimestamp(data["exp"], tz=timezone.utc),
            iat=datetime.fromtimestamp(data["iat"], tz=timezone.utc),
            jti=jti,
            type=data.get("type", "access"),
            roles=data.get("roles", []),
            extra=extra,
            family_id=data.get("family_id"),
        )

    async def blacklist_token(self, jti: str, ttl_seconds: int | None = None) -> None:
        await self.blacklist.add(jti, ttl_seconds)

    async def blacklist_payload(self, payload: TokenPayload) -> None:
        """Blacklist a token for exactly its remaining lifetime.

        Prefer this over ``blacklist_token`` for revocation: a missing TTL makes
        the in-memory store keep the entry forever (unbounded growth) and makes
        the Redis store fall back to the short default TTL, which would let a
        long-lived token (email-verify, password-reset) be replayed once that
        default expires but before the token itself does.
        """
        remaining = int((payload.exp - datetime.now(timezone.utc)).total_seconds())
        await self.blacklist.add(payload.jti, max(1, remaining))

    def create_token_pair(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict[str, Any] | None = None,
        family_id: str | None = None,
    ) -> tuple[str, RefreshTokenMeta]:
        # Create the refresh token first so its resolved family_id (freshly
        # minted when none was passed) can be stamped onto the access token too.
        refresh = self.create_refresh_token(user_id, family_id)
        access = self.create_access_token(user_id, roles, extra, family_id=refresh.family_id)
        return access, refresh


def create_blacklist(config: FullAuthConfig) -> TokenBlacklist:
    """Create a token blacklist backend based on config."""
    if config.BLACKLIST_BACKEND == "redis":
        if not config.REDIS_URL:
            raise ValueError("REDIS_URL must be set when BLACKLIST_BACKEND='redis'")
        return RedisTokenBlacklist(
            redis_url=config.REDIS_URL,
            default_ttl_seconds=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    return InMemoryTokenBlacklist()
