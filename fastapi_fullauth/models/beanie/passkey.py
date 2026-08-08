from datetime import datetime, timezone
from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class PasskeyDocument(Document):
    """Passkey/WebAuthn credential collection. Use directly or subclass.

    class Passkey(PasskeyDocument):
        pass
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    user_id: UUID
    credential_id: str
    public_key: str
    sign_count: int = 0
    device_name: str = ""
    # stored as a native array, unlike the SQL adapters which join on a string
    transports: list[str] = Field(default_factory=list)
    backed_up: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime | None = None

    class Settings:
        name = "fullauth_passkeys"
        indexes = [
            IndexModel("credential_id", unique=True),
            IndexModel("user_id"),
        ]
