from sqlmodel import Field, Relationship

from fastapi_fullauth.models.sqlmodel import (
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
    UserRoleMixin,
)


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class UserRole(UserRoleMixin, table=True):
    pass


class Role(RoleMixin, table=True):
    pass


class User(UserMixin, table=True):
    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(link_model=UserRole)
    refresh_tokens: list[RefreshToken] = Relationship()
