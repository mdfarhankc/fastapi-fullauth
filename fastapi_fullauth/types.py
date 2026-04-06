from datetime import datetime
from typing import Any, Literal, NamedTuple
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

RouteName = Literal[
    "login",
    "logout",
    "register",
    "refresh",
    "verify-email",
    "password-reset",
    "me",
    "verified-me",
    "change-password",
    "update-profile",
    "delete-account",
]


UserID = str | int | UUID


class UserSchema(BaseModel):
    id: UserID
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class CreateUserSchema(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int | None = None


class RefreshTokenMeta(NamedTuple):
    token: str
    expires_at: datetime
    family_id: str


class RefreshToken(BaseModel):
    token: str
    user_id: str
    expires_at: datetime
    family_id: str
    revoked: bool = False


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    jti: str
    type: str  # "access" or "refresh"
    roles: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
    family_id: str | None = None
