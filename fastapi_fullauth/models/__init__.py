"""ORM mixins for fastapi-fullauth.

Pick the adapter you use:

    from fastapi_fullauth.models.sqlalchemy import UserMixin, RefreshTokenMixin
    # or
    from fastapi_fullauth.models.sqlmodel import UserMixin, RefreshTokenMixin

Each mixin sets `__tablename__` and the auth columns. You combine the mixin
with your own DeclarativeBase / SQLModel:

    class Base(DeclarativeBase): ...

    class RefreshToken(RefreshTokenMixin, Base):
        pass

    class User(UserMixin, Base):
        __tablename__ = "fullauth_users"
        # add your app-specific columns / relationships here
"""
