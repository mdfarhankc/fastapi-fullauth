from datetime import datetime, timezone
from typing import Any

from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class OAuthAccountMixin(Model):
    """OAuth-account table. Abstract: subclass with a concrete ``Meta``.

        class OAuthAccount(OAuthAccountMixin):
            class Meta:
                table = "fullauth_oauth_accounts"
                unique_together = (("provider", "provider_user_id"),)

    The ``unique_together`` is required: Tortoise does not inherit an abstract
    ``Meta``, and the constraint is what makes concurrent OAuth callbacks for the
    same identity collapse to one account instead of duplicating.
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    provider = fields.CharField(max_length=50)
    provider_user_id = fields.CharField(max_length=320)
    user: fields.ForeignKeyRelation[Any] = fields.ForeignKeyField(
        "models.User", related_name="oauth_accounts", on_delete=fields.CASCADE
    )
    provider_email = fields.CharField(max_length=320, null=True)
    # TEXT, not VARCHAR(255): provider access/refresh tokens routinely exceed 255
    # chars and would silently truncate on MySQL.
    access_token = fields.TextField(null=True)
    refresh_token = fields.TextField(null=True)
    expires_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(default=lambda: datetime.now(timezone.utc))

    class Meta:
        abstract = True
