from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fastapi_fullauth.adapters.sqlalchemy import (
    FullAuthBase,
    RefreshTokenModel,
    RoleModel,
    UserBase,
)


class User(UserBase, FullAuthBase):
    __tablename__ = "fullauth_users"

    display_name: Mapped[str] = mapped_column(String(100), default="")
    phone: Mapped[str] = mapped_column(String(20), default="")

    roles: Mapped[list[RoleModel]] = relationship(secondary="fullauth_user_roles", lazy="selectin")
    refresh_tokens: Mapped[list[RefreshTokenModel]] = relationship(lazy="noload")
