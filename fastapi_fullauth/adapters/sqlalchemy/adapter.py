from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.adapters.sqlalchemy.models import (
    OAuthAccountModel,
    RefreshTokenModel,
    RoleModel,
    UserBase,
)
from fastapi_fullauth.types import CreateUserSchema, OAuthAccount, RefreshToken, UserSchema

# Map SQLAlchemy column types to Python types for schema auto-derivation
_SA_TYPE_MAP: dict[type, type] = {}


def _get_sa_type_map() -> dict[type, type]:
    if not _SA_TYPE_MAP:
        from sqlalchemy import Boolean, Float, Integer, Numeric, String, Text

        _SA_TYPE_MAP.update(
            {
                String: str,
                Text: str,
                Integer: int,
                Float: float,
                Numeric: float,
                Boolean: bool,
            }
        )
    return _SA_TYPE_MAP


class SQLAlchemyAdapter(AbstractUserAdapter):
    def __init__(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        user_model: type[UserBase],
        user_schema: type[UserSchema] | None = None,
    ) -> None:
        self._session_maker = session_maker
        self._user_model = user_model
        self._user_schema = (
            user_schema if user_schema is not None else self._derive_user_schema(user_model)
        )

    @staticmethod
    def _derive_user_schema(model_class: type) -> type[UserSchema]:
        from pydantic import create_model

        skip = {"hashed_password", "created_at"}
        base_fields = set(UserSchema.model_fields.keys())
        type_map = _get_sa_type_map()
        extra: dict[str, Any] = {}
        for col in model_class.__table__.columns:
            if col.name in base_fields or col.name in skip:
                continue
            py_type = type_map.get(type(col.type), str)
            default = col.default.arg if col.default is not None else None
            extra[col.name] = (py_type | None, default)
        if not extra:
            return UserSchema
        return create_model("DerivedUserSchema", __base__=UserSchema, **extra)

    def _to_schema(self, user) -> UserSchema:
        data = {}
        for field_name in self._user_schema.model_fields:
            val = getattr(user, field_name, None)
            if val is not None:
                data[field_name] = val
        if hasattr(user, "roles"):
            data["roles"] = [r.name for r in user.roles]
        return self._user_schema.model_validate(data)

    async def get_user_by_id(self, user_id: str) -> UserSchema | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        return await self.get_user_by_field("email", email)

    async def get_user_by_field(self, field: str, value: str) -> UserSchema | None:
        column = getattr(self._user_model, field, None)
        if column is None:
            raise ValueError(f"Model has no field '{field}'")
        async with self._session_maker() as session:
            result = await session.execute(select(self._user_model).where(column == value))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def create_user(self, data: CreateUserSchema, hashed_password: str) -> UserSchema:
        async with self._session_maker() as session:
            extra = data.model_dump(exclude={"email", "password"})
            user = self._user_model(
                email=data.email,
                hashed_password=hashed_password,
                **extra,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return self._to_schema(user)

    async def update_user(self, user_id: str, data: dict[str, Any]) -> UserSchema:
        async with self._session_maker() as session:
            await session.execute(
                update(self._user_model).where(self._user_model.id == user_id).values(**data)
            )
            await session.commit()
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user is None:
                raise ValueError(f"User {user_id} not found")
            return self._to_schema(user)

    async def delete_user(self, user_id: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user:
                await session.delete(user)
                await session.commit()

    async def get_user_roles(self, user_id: str) -> list[str]:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user is None:
                return []
            return [r.name for r in user.roles]

    async def get_hashed_password(self, user_id: str) -> str | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model.hashed_password).where(self._user_model.id == user_id)
            )
            return result.scalars().first()

    async def set_password(self, user_id: str, hashed_password: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(self._user_model)
                .where(self._user_model.id == user_id)
                .values(hashed_password=hashed_password)
            )
            await session.commit()

    async def store_refresh_token(self, token: RefreshToken) -> None:
        async with self._session_maker() as session:
            db_token = RefreshTokenModel(
                token=token.token,
                user_id=token.user_id,
                family_id=token.family_id,
                expires_at=token.expires_at,
                revoked=token.revoked,
            )
            session.add(db_token)
            await session.commit()

    async def get_refresh_token(self, token_str: str) -> RefreshToken | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(RefreshTokenModel).where(RefreshTokenModel.token == token_str)
            )
            row = result.scalars().first()
            if row is None:
                return None
            return RefreshToken(
                token=row.token,
                user_id=row.user_id,
                expires_at=row.expires_at,
                family_id=row.family_id,
                revoked=row.revoked,
            )

    async def revoke_refresh_token(self, token_str: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.token == token_str)
                .values(revoked=True)
            )
            await session.commit()

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.family_id == family_id)
                .values(revoked=True)
            )
            await session.commit()

    async def revoke_all_user_refresh_tokens(self, user_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.user_id == user_id)
                .values(revoked=True)
            )
            await session.commit()

    async def set_user_verified(self, user_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(self._user_model)
                .where(self._user_model.id == user_id)
                .values(is_verified=True)
            )
            await session.commit()

    async def assign_role(self, user_id: str, role_name: str) -> None:
        async with self._session_maker() as session:
            # get or create the role
            result = await session.execute(select(RoleModel).where(RoleModel.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = RoleModel(name=role_name)
                session.add(role)
                await session.flush()

            # load user with roles
            result = await session.execute(
                select(self._user_model)
                .options(selectinload(self._user_model.roles))
                .where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user and role not in user.roles:
                user.roles.append(role)
                await session.commit()

    async def remove_role(self, user_id: str, role_name: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model)
                .options(selectinload(self._user_model.roles))
                .where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user:
                user.roles = [r for r in user.roles if r.name != role_name]
                await session.commit()

    # ── OAuth ────────────────────────────────────────────────────────

    def _to_oauth_account(self, row: OAuthAccountModel) -> OAuthAccount:
        return OAuthAccount(
            provider=row.provider,
            provider_user_id=row.provider_user_id,
            user_id=str(row.user_id),
            provider_email=row.provider_email,
            access_token=row.access_token,
            refresh_token=row.refresh_token,
            expires_at=row.expires_at,
        )

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountModel).where(
                    OAuthAccountModel.provider == provider,
                    OAuthAccountModel.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            return self._to_oauth_account(row) if row else None

    async def get_user_oauth_accounts(self, user_id: str) -> list[OAuthAccount]:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountModel).where(OAuthAccountModel.user_id == user_id)
            )
            return [self._to_oauth_account(row) for row in result.scalars().all()]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        async with self._session_maker() as session:
            record = OAuthAccountModel(
                provider=data.provider,
                provider_user_id=data.provider_user_id,
                user_id=data.user_id,
                provider_email=data.provider_email,
                access_token=data.access_token,
                refresh_token=data.refresh_token,
                expires_at=data.expires_at,
            )
            session.add(record)
            await session.commit()
            return data

    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None:
        async with self._session_maker() as session:
            await session.execute(
                update(OAuthAccountModel)
                .where(
                    OAuthAccountModel.provider == provider,
                    OAuthAccountModel.provider_user_id == provider_user_id,
                )
                .values(**data)
            )
            await session.commit()
            return await self.get_oauth_account(provider, provider_user_id)

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountModel).where(
                    OAuthAccountModel.provider == provider,
                    OAuthAccountModel.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            if row:
                await session.delete(row)
                await session.commit()
