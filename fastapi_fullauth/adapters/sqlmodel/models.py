import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, SQLModel


class UserRoleLink(SQLModel, table=True):
    __tablename__ = "fullauth_user_roles"

    user_id: str = Field(foreign_key="fullauth_users.id", primary_key=True, max_length=36)
    role_id: str = Field(foreign_key="fullauth_roles.id", primary_key=True, max_length=36)


class Role(SQLModel, table=True):
    __tablename__ = "fullauth_roles"

    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True, max_length=36)
    name: str = Field(unique=True, index=True, max_length=100)

    users: list["User"] = Relationship(back_populates="roles", link_model=UserRoleLink)


class UserBase(SQLModel):
    """Non-table base with all auth fields. Subclass this with table=True to add custom fields."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True, max_length=36)
    email: str = Field(unique=True, index=True, max_length=320)
    hashed_password: str
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    roles: list[Role] = Relationship(back_populates="users", link_model=UserRoleLink)
    refresh_tokens: list["RefreshTokenRecord"] = Relationship(back_populates="user")


class RefreshTokenRecord(SQLModel, table=True):
    __tablename__ = "fullauth_refresh_tokens"

    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True, max_length=36)
    token: str = Field(unique=True, index=True)
    user_id: str = Field(foreign_key="fullauth_users.id", max_length=36)
    family_id: str = Field(index=True, max_length=36)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    revoked: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    user: User | None = Relationship(back_populates="refresh_tokens")
