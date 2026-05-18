from uuid import UUID

from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class RolePermissionMixin(SQLModel):
    """Role-permission association. Combine with ``table=True``:

    class RolePermission(RolePermissionMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_role_permissions"

    role_id: UUID = Field(foreign_key="fullauth_roles.id", primary_key=True)
    permission_id: UUID = Field(foreign_key="fullauth_permissions.id", primary_key=True)


class PermissionMixin(SQLModel):
    """Permission table. Combine with ``table=True``:

    class Permission(PermissionMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_permissions"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=200)
    description: str = Field(default="", max_length=500)
