from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from uuid_utils import uuid7


class FullAuthBase(DeclarativeBase):
    pass


class UserBase:
    """Mixin with all auth columns. Subclass this + FullAuthBase to create your user table:

    class User(UserBase, FullAuthBase):
        __tablename__ = "fullauth_users"

        display_name: Mapped[str] = mapped_column(String(100), default="")
        roles: Mapped[list[RoleModel]] = relationship(
            secondary="fullauth_user_roles", lazy="selectin"
        )
        refresh_tokens: Mapped[list[RefreshTokenModel]] = relationship(lazy="noload")
    """

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    email: Mapped[str] = mapped_column(unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class PermissionModel(FullAuthBase):
    __tablename__ = "fullauth_permissions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="")


class RoleModel(FullAuthBase):
    __tablename__ = "fullauth_roles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)


class UserRoleModel(FullAuthBase):
    __tablename__ = "fullauth_user_roles"

    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )


class RolePermissionModel(FullAuthBase):
    __tablename__ = "fullauth_role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_permissions.id", ondelete="CASCADE"), primary_key=True
    )


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
