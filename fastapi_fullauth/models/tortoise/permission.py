from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class PermissionMixin(Model):
    """Permission table. Abstract: subclass with a concrete ``Meta``.

        class Permission(PermissionMixin):
            class Meta:
                table = "fullauth_permissions"

    Name the concrete class ``Permission`` and register it under the ``models``
    app label; the role-permission M2M on ``Role`` references
    ``"models.Permission"``.
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    name = fields.CharField(max_length=200, unique=True)
    description = fields.CharField(max_length=500, default="")

    class Meta:
        abstract = True
