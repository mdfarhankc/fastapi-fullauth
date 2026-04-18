from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, UniqueConstraint
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class OAuthAccountRecord(SQLModel, table=True):
    __tablename__ = "fullauth_oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_user"),
    )

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    provider: str = Field(max_length=50)
    provider_user_id: str = Field(max_length=320)
    user_id: UUID = Field(foreign_key="fullauth_users.id")
    provider_email: str | None = Field(default=None, max_length=320)
    access_token: str | None = Field(default=None)
    refresh_token: str | None = Field(default=None)
    expires_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
