from uuid import UUID

from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class RolePermissionLink(SQLModel, table=True):
    __tablename__ = "fullauth_role_permissions"

    role_id: UUID = Field(foreign_key="fullauth_roles.id", primary_key=True)
    permission_id: UUID = Field(foreign_key="fullauth_permissions.id", primary_key=True)


class Permission(SQLModel, table=True):
    __tablename__ = "fullauth_permissions"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=200)
    description: str = Field(default="", max_length=500)
