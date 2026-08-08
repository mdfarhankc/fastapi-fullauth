from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class RoleDocument(Document):
    """Role collection. Use directly or subclass.

        class Role(RoleDocument):
            pass

    A role's granted permissions are stored as an embedded ``permissions`` array
    on the role document (the authoritative role -> permission mapping), so
    resolving a user's permissions is a single read of the roles named on the
    user. The separate permission collection (see ``PermissionDocument``) is just
    the catalog of known permission names.
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    name: str
    permissions: list[str] = Field(default_factory=list)

    class Settings:
        name = "fullauth_roles"
        indexes = [IndexModel("name", unique=True)]
