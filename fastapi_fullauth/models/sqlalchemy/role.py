from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from uuid_utils import uuid7


class RoleMixin:
    """Role table. Combine with your DeclarativeBase:

    class Role(RoleMixin, Base):
        pass
    """

    __tablename__ = "fullauth_roles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    # String(100) + index mirrors the SQLModel mixin; an unbounded VARCHAR
    # unique key fails DDL on MySQL.
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)


class UserRoleMixin:
    """User-role association. Combine with your DeclarativeBase:

    class UserRole(UserRoleMixin, Base):
        pass
    """

    __tablename__ = "fullauth_user_roles"

    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("fullauth_roles.id", ondelete="CASCADE"), primary_key=True
    )
