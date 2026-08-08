from uuid import UUID

from beanie import Document
from pydantic import Field
from pymongo import IndexModel

from fastapi_fullauth.models.beanie._common import uuid7


class PermissionDocument(Document):
    """Permission catalog collection. Use directly or subclass.

        class Permission(PermissionDocument):
            pass

    This is the registry of known permission names (with an optional
    description). The role -> permission grants themselves live in the embedded
    ``permissions`` array on ``RoleDocument``; this collection mirrors the SQL
    adapters' permission table so the ``permission`` feature has a model to gate
    on. Required only when you pass ``permission_model`` to enable permissions.
    """

    id: UUID = Field(default_factory=uuid7)  # type: ignore[assignment]
    name: str
    description: str = ""

    class Settings:
        name = "fullauth_permissions"
        indexes = [IndexModel("name", unique=True)]
