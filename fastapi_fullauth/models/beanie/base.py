from datetime import datetime, timezone
from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class UserDocument(Document):
    """User collection. Use directly or subclass to add fields.

        class User(UserDocument):
            display_name: str = ""

    Roles are stored as an embedded ``roles`` array on the user document rather
    than in a join collection - MongoDB has no foreign keys, so denormalizing the
    membership onto the user is the idiomatic shape and keeps role lookups to a
    single read. Pass ``User`` to ``BeanieAdapter(user_model=...)`` and register
    it with ``init_beanie(document_models=[User, ...])``.
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    email: str
    # None so OAuth-only users can exist without a password.
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "fullauth_users"
        indexes = [IndexModel("email", unique=True)]


class RefreshTokenDocument(Document):
    """Refresh-token collection. Use directly or subclass.

    class RefreshToken(RefreshTokenDocument):
        pass
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    token: str
    user_id: UUID
    family_id: str
    expires_at: datetime
    revoked: bool = False
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "fullauth_refresh_tokens"
        indexes = [
            IndexModel("token", unique=True),
            IndexModel("user_id"),
            IndexModel("family_id"),
        ]
