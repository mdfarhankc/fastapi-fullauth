from datetime import datetime, timezone
from typing import Any

from tortoise import fields
from tortoise.models import Model

from fastapi_fullauth.models.tortoise._common import uuid7


class UserMixin(Model):
    """Auth columns for the User table. Abstract: subclass with a concrete ``Meta``.

        class User(UserMixin):
            # opt into roles by declaring the M2M to your Role model
            roles = fields.ManyToManyField(
                "models.Role", related_name="users", through="fullauth_user_roles"
            )

            class Meta:
                table = "fullauth_users"

    Name the concrete class ``User`` and register your models under the Tortoise
    app label ``models`` (``modules={"models": ["yourapp.models"]}``): the
    foreign keys in the other mixins reference ``"models.User"``. Tortoise does
    not inherit an abstract ``Meta``, so every concrete subclass must declare its
    own ``Meta`` with ``table``.
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    email = fields.CharField(max_length=320, unique=True)
    # Nullable so OAuth-only users can exist without a password; TEXT because an
    # argon2id hash (~97 chars) overflows the VARCHAR(255) default on some backends.
    hashed_password = fields.TextField(null=True)
    is_active = fields.BooleanField(default=True)
    is_verified = fields.BooleanField(default=False)
    is_superuser = fields.BooleanField(default=False)
    created_at = fields.DatetimeField(default=lambda: datetime.now(timezone.utc))

    class Meta:
        abstract = True


class RefreshTokenMixin(Model):
    """Refresh-token table. Abstract: subclass with a concrete ``Meta``.

    class RefreshToken(RefreshTokenMixin):
        class Meta:
            table = "fullauth_refresh_tokens"
    """

    id = fields.UUIDField(primary_key=True, default=uuid7)
    token = fields.CharField(max_length=512, unique=True)
    user: fields.ForeignKeyRelation[Any] = fields.ForeignKeyField(
        "models.User", related_name="refresh_tokens", on_delete=fields.CASCADE
    )
    family_id = fields.CharField(max_length=36, db_index=True)
    expires_at = fields.DatetimeField()
    revoked = fields.BooleanField(default=False)
    user_agent = fields.CharField(max_length=512, null=True)
    ip_address = fields.CharField(max_length=45, null=True)
    created_at = fields.DatetimeField(default=lambda: datetime.now(timezone.utc))

    class Meta:
        abstract = True
