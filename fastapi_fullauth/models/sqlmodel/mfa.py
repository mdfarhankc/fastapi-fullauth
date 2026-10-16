from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class MFAMixin(SQLModel):
    """TOTP second-factor table. Combine with ``table=True``:

    class MFA(MFAMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_mfa"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    # One factor per user, enforced by the database rather than by a read first:
    # two concurrent enrolments must not both succeed.
    user_id: UUID = Field(
        foreign_key="fullauth_users.id", ondelete="CASCADE", unique=True, index=True
    )
    secret: str = Field(max_length=64)
    # NULL until a first valid code proves the authenticator was set up. An
    # unconfirmed row never gates a sign-in.
    confirmed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    # The most recent accepted time step; a code is refused once it is not
    # strictly greater, which is what stops a code being used twice.
    last_counter: int = Field(default=0)
    # Comma-separated sha256 digests, like the passkey transports column. Text,
    # not VARCHAR: ten 64-character digests overflow the 255 default on MySQL.
    recovery_codes: str = Field(default="", sa_column=Column(Text, nullable=False, default=""))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
