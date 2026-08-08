from datetime import datetime, timezone
from typing import Any

from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class PasskeyMixin(Model):
    """Passkey credential table. Abstract: subclass with a concrete ``Meta``.

    class Passkey(PasskeyMixin):
        class Meta:
            table = "fullauth_passkeys"
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    user: fields.ForeignKeyRelation[Any] = fields.ForeignKeyField(
        "models.User", related_name="passkeys", on_delete=fields.CASCADE, db_index=True
    )
    # CharField (not TextField): Tortoise can't build a unique index on TEXT,
    # and MySQL has the same limitation. 512 matches the refresh-token width.
    credential_id = fields.CharField(max_length=512, unique=True)
    public_key = fields.TextField()
    sign_count = fields.IntField(default=0)
    device_name = fields.CharField(max_length=200, default="")
    # comma-separated transports, e.g. "internal,hybrid"
    transports = fields.CharField(max_length=200, default="")
    backed_up = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(default=lambda: datetime.now(timezone.utc))
    last_used_at = fields.DatetimeField(null=True, default=None)

    class Meta:
        abstract = True
