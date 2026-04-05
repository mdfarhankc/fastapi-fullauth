from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.adapters.sqlmodel.models import RefreshTokenRecord, Role, UserBase
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserSchema


class SQLModelAdapter(AbstractUserAdapter):
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

        skip = {"hashed_password", "created_at", "roles", "refresh_tokens"}
        base_fields = set(UserSchema.model_fields.keys())
        extra: dict[str, Any] = {}
        for name, field in model_class.model_fields.items():
            if name in base_fields or name in skip:
                continue
            default = field.default if field.default is not None else None
            # type: ignore[operator]
            extra[name] = (field.annotation | None, default)
        if not extra:
            return UserSchema
        return create_model("DerivedUserSchema", __base__=UserSchema, **extra)

    def _user_query(self):
        # type: ignore[arg-type]
        return select(self._user_model).options(selectinload(self._user_model.roles))

    def _to_schema(self, user) -> UserSchema:
        # convert Role objects to role name strings before validation
        data = {}
        for field_name in self._user_schema.model_fields:
            val = getattr(user, field_name, None)
            if val is not None:
                data[field_name] = val
        # roles need special handling: list[Role] -> list[str]
        if hasattr(user, "roles"):
            data["roles"] = [r.name for r in user.roles]
        return self._user_schema.model_validate(data)

    async def get_user_by_id(self, user_id: str) -> UserSchema | None:
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        return await self.get_user_by_field("email", email)

    async def get_user_by_field(self, field: str, value: str) -> UserSchema | None:
        column = getattr(self._user_model, field, None)
        if column is None:
            raise ValueError(f"Model has no field '{field}'")
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(column == value))
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
            # re-fetch with roles loaded
            result = await session.execute(self._user_query().where(self._user_model.id == user.id))
            user = result.scalars().first()  # type: ignore[assignment]
            return self._to_schema(user)  # type: ignore[arg-type]

    async def update_user(self, user_id: str, data: dict[str, Any]) -> UserSchema:
        async with self._session_maker() as session:
            await session.execute(
                update(self._user_model).where(self._user_model.id == user_id).values(**data)
            )
            await session.commit()
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
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
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
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
            db_token = RefreshTokenRecord(
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
                select(RefreshTokenRecord).where(RefreshTokenRecord.token == token_str)
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
                update(RefreshTokenRecord)
                .where(RefreshTokenRecord.token == token_str)
                .values(revoked=True)
            )
            await session.commit()

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenRecord)
                .where(RefreshTokenRecord.family_id == family_id)
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
            result = await session.execute(select(Role).where(Role.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = Role(name=role_name)
                session.add(role)
                await session.flush()

            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            if user and role not in user.roles:
                user.roles.append(role)
                session.add(user)
                await session.commit()

    async def remove_role(self, user_id: str, role_name: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            if user:
                user.roles = [r for r in user.roles if r.name != role_name]
                session.add(user)
                await session.commit()
