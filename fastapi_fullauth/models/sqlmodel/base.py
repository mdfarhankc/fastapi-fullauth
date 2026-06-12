from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class UserMixin(SQLModel):
    """Auth fields for the User table. Combine with ``table=True``:

        class User(UserMixin, table=True):
            display_name: str = Field(default="", max_length=100)
            roles: list[Role] = Relationship(link_model=UserRole)
            refresh_tokens: list[RefreshToken] = Relationship()

    Overriding ``__tablename__`` will break ForeignKey references in the other
    mixins (which point at ``fullauth_users.id``). Keep the default unless you
    also override the referencing FKs.
    """

    __tablename__ = "fullauth_users"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=320)
    # argon2id output is ~97 chars; VARCHAR(255) default on MySQL/MSSQL silently truncates.
    # Nullable so OAuth-only users can exist without a password.
    hashed_password: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RefreshTokenMixin(SQLModel):
    """Refresh-token table. Combine with ``table=True``:

    class RefreshToken(RefreshTokenMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_refresh_tokens"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    token: str = Field(unique=True, index=True)
    user_id: UUID = Field(foreign_key="fullauth_users.id")
    family_id: str = Field(index=True, max_length=36)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    revoked: bool = Field(default=False)
    user_agent: str | None = Field(default=None, max_length=512)
    ip_address: str | None = Field(default=None, max_length=45)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
