from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7


class UserMixin:
    """Auth columns for the User table. Combine with your DeclarativeBase.

    Example:

        class Base(DeclarativeBase):
            pass

        class User(UserMixin, Base):
            display_name: Mapped[str] = mapped_column(String(100), default="")
            roles: Mapped[list[Role]] = relationship(
                secondary="fullauth_user_roles", lazy="selectin"
            )
            refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")

    Overriding ``__tablename__`` will break the ForeignKey references in the
    other mixins (which point at ``fullauth_users.id``). Keep the default
    unless you also override the referencing FKs.
    """

    __tablename__ = "fullauth_users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(unique=True, index=True, nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class RefreshTokenMixin:
    """Refresh-token table. Combine with your DeclarativeBase:

    class RefreshToken(RefreshTokenMixin, Base):
        pass
    """

    __tablename__ = "fullauth_refresh_tokens"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    token: Mapped[str] = mapped_column(Text, unique=True, index=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_users.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[str] = mapped_column(index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
