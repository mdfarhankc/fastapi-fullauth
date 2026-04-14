from sqlmodel import Field, Relationship

from fastapi_fullauth.adapters.sqlmodel.models.base import RefreshTokenRecord, UserBase
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink


class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()
