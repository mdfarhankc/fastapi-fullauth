import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.exceptions import TokenBlacklistedError, TokenError, TokenExpiredError
from fastapi_fullauth.types import RefreshTokenMeta, TokenPayload

logger = logging.getLogger("fastapi_fullauth.tokens")


class TokenBlacklist:
    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        raise NotImplementedError

    async def is_blacklisted(self, jti: str) -> bool:
        raise NotImplementedError


class InMemoryBlacklist(TokenBlacklist):
    def __init__(self) -> None:
        self._blacklisted: dict[str, float | None] = {}

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        expires_at = (time.monotonic() + ttl_seconds) if ttl_seconds else None
        self._blacklisted[jti] = expires_at

    async def is_blacklisted(self, jti: str) -> bool:
        expires_at = self._blacklisted.get(jti)
        if expires_at is None and jti not in self._blacklisted:
            return False
        if expires_at is not None and time.monotonic() > expires_at:
            del self._blacklisted[jti]
            return False
        return True


class TokenEngine:
    def __init__(self, config: FullAuthConfig, blacklist: TokenBlacklist | None = None) -> None:
        self.config = config
        self.blacklist = blacklist or InMemoryBlacklist()

    def create_access_token(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict | None = None,
        expire_seconds: int | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        if expire_seconds is not None:
            expires = now + timedelta(seconds=expire_seconds)
        else:
            expires = now + timedelta(minutes=self.config.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": user_id,
            "exp": expires,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": "access",
            "roles": roles or [],
            "extra": extra or {},
        }
        return jwt.encode(payload, self.config.SECRET_KEY, algorithm=self.config.ALGORITHM)

    def create_refresh_token(
        self,
        user_id: str,
        family_id: str | None = None,
    ) -> RefreshTokenMeta:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=self.config.REFRESH_TOKEN_EXPIRE_DAYS)
        resolved_family_id = family_id or uuid.uuid4().hex
        payload = {
            "sub": user_id,
            "exp": expires_at,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": "refresh",
            "family_id": resolved_family_id,
        }
        token = jwt.encode(payload, self.config.SECRET_KEY, algorithm=self.config.ALGORITHM)
        return RefreshTokenMeta(token=token, expires_at=expires_at, family_id=resolved_family_id)

    async def decode_token(self, token: str) -> TokenPayload:
        try:
            data = jwt.decode(
                token,
                self.config.SECRET_KEY,
                algorithms=[self.config.ALGORITHM],
                leeway=self.config.JWT_LEEWAY_SECONDS,
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Token decode failed — expired")
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.debug("Token decode failed — invalid: %s", e)
            raise TokenError(f"Invalid token: {e}")

        jti = data.get("jti", "")
        if self.config.BLACKLIST_ENABLED and await self.blacklist.is_blacklisted(jti):
            logger.warning("Blacklisted token used: jti=%s, sub=%s", jti, data.get("sub"))
            raise TokenBlacklistedError("Token has been revoked")

        return TokenPayload(
            sub=data["sub"],
            exp=datetime.fromtimestamp(data["exp"], tz=timezone.utc),
            iat=datetime.fromtimestamp(data["iat"], tz=timezone.utc),
            jti=jti,
            type=data.get("type", "access"),
            roles=data.get("roles", []),
            extra=data.get("extra", {}),
            family_id=data.get("family_id"),
        )

    async def blacklist_token(self, jti: str, ttl_seconds: int | None = None) -> None:
        await self.blacklist.add(jti, ttl_seconds)

    def create_token_pair(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict | None = None,
        family_id: str | None = None,
    ) -> tuple[str, RefreshTokenMeta]:
        access = self.create_access_token(user_id, roles, extra)
        refresh = self.create_refresh_token(user_id, family_id)
        return access, refresh


def create_blacklist(config: FullAuthConfig) -> TokenBlacklist:
    """Create a token blacklist backend based on config."""
    if config.BLACKLIST_BACKEND == "redis":
        if not config.REDIS_URL:
            raise ValueError("REDIS_URL must be set when BLACKLIST_BACKEND='redis'")
        from fastapi_fullauth.core.redis_blacklist import RedisBlacklist

        return RedisBlacklist(
            redis_url=config.REDIS_URL,
            default_ttl_seconds=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    return InMemoryBlacklist()
