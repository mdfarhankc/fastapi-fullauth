from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class PasskeyRecord(SQLModel, table=True):
    __tablename__ = "fullauth_passkeys"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    user_id: UUID = Field(foreign_key="fullauth_users.id", index=True)
    credential_id: str = Field(sa_column=Column(Text, unique=True, index=True, nullable=False))
    public_key: str = Field(sa_column=Column(Text, nullable=False))
    sign_count: int = Field(default=0)
    device_name: str = Field(default="", max_length=200)
    transports: str = Field(default="")  # comma-separated: "internal,hybrid"
    backed_up: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
