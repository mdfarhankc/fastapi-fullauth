from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.exceptions import TokenBlacklistedError, TokenError, TokenExpiredError
from fastapi_fullauth.types import TokenPayload


class TokenEngine:
    def __init__(self, config: FullAuthConfig, blacklist: TokenBlacklist | None = None) -> None:
        self.config = config
        self.blacklist = blacklist or InMemoryBlacklist()

    def create_access_token(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "exp": now + timedelta(minutes=self.config.ACCESS_TOKEN_EXPIRE_MINUTES),
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
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "exp": now + timedelta(days=self.config.REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": "refresh",
            "family_id": family_id or uuid.uuid4().hex,
        }
        return jwt.encode(payload, self.config.SECRET_KEY, algorithm=self.config.ALGORITHM)

    def decode_token(self, token: str) -> TokenPayload:
        try:
            data = jwt.decode(token, self.config.SECRET_KEY,
                              algorithms=[self.config.ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenError(f"Invalid token: {e}")

        jti = data.get("jti", "")
        if self.config.BLACKLIST_ENABLED and self.blacklist.is_blacklisted(jti):
            raise TokenBlacklistedError("Token has been revoked")

        return TokenPayload(
            sub=data["sub"],
            exp=datetime.fromtimestamp(data["exp"], tz=timezone.utc),
            iat=datetime.fromtimestamp(data["iat"], tz=timezone.utc),
            jti=jti,
            type=data.get("type", "access"),
            roles=data.get("roles", []),
            extra=data.get("extra", {}),
        )

    def blacklist_token(self, jti: str) -> None:
        self.blacklist.add(jti)

    def create_token_pair(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra: dict | None = None,
        family_id: str | None = None,
    ) -> tuple[str, str]:
        access = self.create_access_token(user_id, roles, extra)
        refresh = self.create_refresh_token(user_id, family_id)
        return access, refresh


class TokenBlacklist:
    """Interface for token blacklist backends."""

    def add(self, jti: str) -> None:
        raise NotImplementedError

    def is_blacklisted(self, jti: str) -> bool:
        raise NotImplementedError


class InMemoryBlacklist(TokenBlacklist):
    def __init__(self) -> None:
        self._blacklisted: set[str] = set()

    def add(self, jti: str) -> None:
        self._blacklisted.add(jti)

    def is_blacklisted(self, jti: str) -> bool:
        return jti in self._blacklisted
