from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from fastapi_fullauth.models.sqlalchemy import (
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
    UserRoleMixin,
)


class Base(DeclarativeBase):
    pass


class RefreshToken(RefreshTokenMixin, Base):
    pass


class Role(RoleMixin, Base):
    pass


class UserRole(UserRoleMixin, Base):
    pass


class User(UserMixin, Base):
    display_name: Mapped[str] = mapped_column(String(100), default="")
    phone: Mapped[str] = mapped_column(String(20), default="")

    roles: Mapped[list[Role]] = relationship(secondary="fullauth_user_roles", lazy="selectin")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(lazy="noload")
