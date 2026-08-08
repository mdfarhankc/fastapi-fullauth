from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class RoleMixin(Model):
    """Role table. Abstract: subclass with a concrete ``Meta``.

        class Role(RoleMixin):
            # opt into permissions by declaring the M2M to your Permission model
            permissions = fields.ManyToManyField(
                "models.Permission",
                related_name="roles",
                through="fullauth_role_permissions",
            )

            class Meta:
                table = "fullauth_roles"

    Name the concrete class ``Role`` and register it under the ``models`` app
    label; the user-role M2M on ``User`` references ``"models.Role"``. The
    ``related_name="roles"`` on the permissions M2M is required - the adapter
    resolves a role's permissions through that reverse accessor.
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    name = fields.CharField(max_length=100, unique=True)

    class Meta:
        abstract = True
