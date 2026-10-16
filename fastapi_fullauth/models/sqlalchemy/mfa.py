from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7


class MFAMixin:
    """TOTP second-factor table. Combine with your DeclarativeBase:

    class MFA(MFAMixin, Base):
        pass
    """

    __tablename__ = "fullauth_mfa"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    # One factor per user, enforced by the database rather than by a read first:
    # two concurrent enrolments must not both succeed.
    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("fullauth_users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
    # NULL until a first valid code proves the authenticator was set up. An
    # unconfirmed row never gates a sign-in.
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The most recent accepted time step; a code is refused once it is not
    # strictly greater, which is what stops a code being used twice.
    last_counter: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Comma-separated sha256 digests, like the passkey transports column. Text,
    # not VARCHAR: ten 64-character digests overflow the 255 default on MySQL.
    recovery_codes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
