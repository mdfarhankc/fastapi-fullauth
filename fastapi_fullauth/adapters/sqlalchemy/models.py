from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from uuid_utils import uuid7


class FullAuthBase(DeclarativeBase):
    pass


class UserModel(FullAuthBase):
    __tablename__ = "fullauth_users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    roles: Mapped[list[RoleModel]] = relationship(
        secondary="fullauth_user_roles", back_populates="users", lazy="selectin"
    )
    refresh_tokens: Mapped[list[RefreshTokenModel]] = relationship(
        back_populates="user", lazy="noload"
    )


class RoleModel(FullAuthBase):
    __tablename__ = "fullauth_roles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)

    users: Mapped[list[UserModel]] = relationship(
        secondary="fullauth_user_roles", back_populates="roles", lazy="noload"
    )


class UserRoleModel(FullAuthBase):
    __tablename__ = "fullauth_user_roles"

    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )


class RefreshTokenModel(FullAuthBase):
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

    user: Mapped[UserModel] = relationship(back_populates="refresh_tokens", lazy="noload")
