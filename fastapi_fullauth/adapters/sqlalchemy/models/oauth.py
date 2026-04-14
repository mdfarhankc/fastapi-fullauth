from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7

from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase


class OAuthAccountModel(FullAuthBase):
    __tablename__ = "fullauth_oauth_accounts"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    provider: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_users.id", ondelete="CASCADE"), nullable=False
    )
    provider_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
