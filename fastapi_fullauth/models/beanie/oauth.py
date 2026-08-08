from datetime import datetime, timezone
from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class OAuthAccountDocument(Document):
    """OAuth-account collection. Use directly or subclass.

        class OAuthAccount(OAuthAccountDocument):
            pass

    The compound unique index on ``(provider, provider_user_id)`` is what makes
    concurrent OAuth callbacks for the same identity collapse to one account
    instead of duplicating - the adapter relies on the resulting
    ``DuplicateKeyError`` to stay idempotent.
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    provider: str
    provider_user_id: str
    user_id: UUID
    provider_email: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "fullauth_oauth_accounts"
        indexes = [
            IndexModel([("provider", 1), ("provider_user_id", 1)], unique=True),
            IndexModel("user_id"),
        ]
