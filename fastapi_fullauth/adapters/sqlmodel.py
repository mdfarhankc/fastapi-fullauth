from sqlalchemy.ext.asyncio import AsyncSession as SAAsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession as SMAsyncSession

from fastapi_fullauth.adapters._sqlalchemy_base import _BaseSQLAlchemyAdapter
from fastapi_fullauth.models.sqlmodel import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    RolePermissionMixin,
    UserMixin,
    UserRoleMixin,
)
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    UserSchema,
    UserSchemaType,
)


class SQLModelAdapter(_BaseSQLAlchemyAdapter[UserSchemaType, CreateUserSchemaType]):
    _adapter_name = "SQLModelAdapter"

    def __init__(
        self,
        session_maker: async_sessionmaker[SMAsyncSession | SAAsyncSession],
        *,
        user_model: type[UserMixin],
        refresh_token_model: type[RefreshTokenMixin],
        role_model: type[RoleMixin] | None = None,
        user_role_model: type[UserRoleMixin] | None = None,
        permission_model: type[PermissionMixin] | None = None,
        role_permission_model: type[RolePermissionMixin] | None = None,
        oauth_account_model: type[OAuthAccountMixin] | None = None,
        passkey_model: type[PasskeyMixin] | None = None,
        user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
        create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
    ) -> None:
        self._configure(
            session_maker,
            user_model=user_model,
            refresh_token_model=refresh_token_model,
            role_model=role_model,
            user_role_model=user_role_model,
            permission_model=permission_model,
            role_permission_model=role_permission_model,
            oauth_account_model=oauth_account_model,
            passkey_model=passkey_model,
            user_schema=user_schema,
            create_user_schema=create_user_schema,
        )
