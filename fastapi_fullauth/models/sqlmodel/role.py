from uuid import UUID

from sqlmodel import Field, SQLModel
from uuid_utils import uuid7


class UserRoleMixin(SQLModel):
    """User-role association. Combine with ``table=True``:

    class UserRole(UserRoleMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_user_roles"

    user_id: UUID = Field(foreign_key="fullauth_users.id", primary_key=True)
    role_id: UUID = Field(foreign_key="fullauth_roles.id", primary_key=True)


class RoleMixin(SQLModel):
    """Role table. Combine with ``table=True``:

    class Role(RoleMixin, table=True):
        pass
    """

    __tablename__ = "fullauth_roles"

    id: UUID = Field(default_factory=uuid7, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=100)
