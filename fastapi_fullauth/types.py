from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, ClassVar, Literal, NamedTuple
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field
from typing_extensions import TypeVar

UserID = UUID


class UserSchema(BaseModel):
    id: UserID
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False

    model_config = {"from_attributes": True}

    PROTECTED_FIELDS: ClassVar[set[str]] = {
        "id",
        "email",
        "hashed_password",
        "has_usable_password",
        "is_active",
        "is_verified",
        "is_superuser",
        "roles",
        "password",
        "created_at",
        "refresh_tokens",
    }


class CreateUserSchema(BaseModel):
    email: EmailStr
    password: str


UserSchemaType = TypeVar("UserSchemaType", bound=UserSchema, default=UserSchema)
CreateUserSchemaType = TypeVar(
    "CreateUserSchemaType", bound=CreateUserSchema, default=CreateUserSchema
)


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
    user_id: UUID
    expires_at: datetime
    family_id: str
    revoked: bool = False


class OAuthAccount(BaseModel):
    provider: str
    provider_user_id: str
    user_id: UUID
    provider_email: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None

    model_config = {"from_attributes": True}


class OAuthUserInfo(BaseModel):
    provider: str
    provider_user_id: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    jti: str
    type: str  # "access" or "refresh"
    roles: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
    family_id: str | None = None


class PasskeyCredential(BaseModel):
    id: UUID
    user_id: UUID
    credential_id: str
    public_key: str
    sign_count: int = 0
    device_name: str = ""
    transports: list[str] = Field(default_factory=list)
    backed_up: bool = False
    created_at: datetime | None = None
    last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


RouterName = Literal["auth", "profile", "verify", "admin", "oauth", "passkey"]
TokenClaimsBuilder = Callable[[UserSchema], Awaitable[dict[str, Any]]]
