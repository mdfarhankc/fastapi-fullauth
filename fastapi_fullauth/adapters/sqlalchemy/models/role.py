from uuid import UUID

from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7

from fastapi_fullauth.adapters.sqlalchemy.models.base import FullAuthBase


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
