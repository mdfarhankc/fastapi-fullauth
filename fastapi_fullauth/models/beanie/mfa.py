from datetime import datetime
from datetime import timezone as _tz
from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class MFADocument(Document):
    """TOTP second-factor collection. Use directly or subclass.

    class MFA(MFADocument):
        pass
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    user_id: UUID
    secret: str
    # None until a first valid code proves the authenticator was set up. An
    # unconfirmed document never gates a sign-in.
    confirmed_at: datetime | None = None
    # The most recent accepted time step; a code is refused once it is not
    # strictly greater, which is what stops a code being used twice.
    last_counter: int = 0
    # A native array here, unlike the SQL adapters which join on a string.
    recovery_codes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(_tz.utc))

    class Settings:
        name = "fullauth_mfa"
        indexes = [IndexModel("user_id", unique=True)]
