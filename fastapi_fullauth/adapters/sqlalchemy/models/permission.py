from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7

from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase


class PermissionModel(FullAuthBase):
    __tablename__ = "fullauth_permissions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="")


class RolePermissionModel(FullAuthBase):
    __tablename__ = "fullauth_role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_permissions.id", ondelete="CASCADE"), primary_key=True
    )
