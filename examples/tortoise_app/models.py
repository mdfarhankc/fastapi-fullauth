from tortoise import fields

from fastapi_fullauth.models.tortoise import (
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
)


class Role(RoleMixin):
    class Meta:
        table = "fullauth_roles"


class RefreshToken(RefreshTokenMixin):
    class Meta:
        table = "fullauth_refresh_tokens"


class User(UserMixin):
    display_name = fields.CharField(max_length=100, default="")
    phone = fields.CharField(max_length=20, default="")

    # Native Tortoise M2M; related_name="users" is what the adapter resolves
    # roles through. No separate user_role_model - Tortoise owns the table.
    roles = fields.ManyToManyField(
        "models.Role", related_name="users", through="fullauth_user_roles"
    )

    class Meta:
        table = "fullauth_users"
