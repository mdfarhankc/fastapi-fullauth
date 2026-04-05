from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class UserRoleLink(SQLModel, table=True):
    __tablename__ = "fullauth_user_roles"

    user_id: UUID = Field(foreign_key="fullauth_users.id", primary_key=True)
    role_id: UUID = Field(foreign_key="fullauth_roles.id", primary_key=True)


class Role(SQLModel, table=True):
    __tablename__ = "fullauth_roles"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=100)


class UserBase(SQLModel):
    """Mixin with all auth fields. Subclass this to create your user table:

    class User(UserBase, table=True):
        __tablename__ = "fullauth_users"

        full_name: str = Field(default="", max_length=100)
        roles: list[Role] = Relationship(link_model=UserRoleLink)
        refresh_tokens: list["RefreshTokenRecord"] = Relationship()
    """

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=320)
    hashed_password: str
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RefreshTokenRecord(SQLModel, table=True):
    __tablename__ = "fullauth_refresh_tokens"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    token: str = Field(unique=True, index=True)
    user_id: UUID = Field(foreign_key="fullauth_users.id")
    family_id: str = Field(index=True, max_length=36)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    revoked: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
