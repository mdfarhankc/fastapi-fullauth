from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7


class PermissionMixin:
    """Permission table. Combine with your DeclarativeBase:

    class Permission(PermissionMixin, Base):
        pass
    """

    __tablename__ = "fullauth_permissions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="")


class RolePermissionMixin:
    """Role-permission association. Combine with your DeclarativeBase:

    class RolePermission(RolePermissionMixin, Base):
        pass
    """

    __tablename__ = "fullauth_role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_permissions.id", ondelete="CASCADE"), primary_key=True
    )
