from datetime import datetime, timezone
from typing import Any

from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class MFAMixin(Model):
    """TOTP second-factor table. Abstract: subclass with a concrete ``Meta``.

    class MFA(MFAMixin):
        class Meta:
            table = "fullauth_mfa"
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    # One factor per user, enforced by the database rather than by a read
    # first: two concurrent enrolments must not both succeed.
    user: fields.OneToOneRelation[Any] = fields.OneToOneField(
        "models.User", related_name="mfa", on_delete=fields.CASCADE
    )
    secret = fields.CharField(max_length=64)
    # NULL until a first valid code proves the authenticator was set up. An
    # unconfirmed row never gates a sign-in.
    confirmed_at = fields.DatetimeField(null=True, default=None)
    # The most recent accepted time step; a code is refused once it is not
    # strictly greater, which is what stops a code being used twice.
    last_counter = fields.IntField(default=0)
    # Comma-separated sha256 digests, like the passkey transports column.
    recovery_codes = fields.TextField(default="")
    created_at = fields.DatetimeField(default=lambda: datetime.now(timezone.utc))

    class Meta:
        abstract = True
