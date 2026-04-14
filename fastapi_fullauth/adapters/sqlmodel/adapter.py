from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession as SAAsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlmodel.ext.asyncio.session import AsyncSession as SMAsyncSession

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.adapters.sqlmodel.models import (
    OAuthAccountRecord,
    Permission,
    RefreshTokenRecord,
    Role,
    RolePermissionLink,
    UserBase,
)
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    OAuthAccount,
    RefreshToken,
    UserID,
    UserSchema,
    UserSchemaType,
)


class SQLModelAdapter(AbstractUserAdapter[UserSchemaType, CreateUserSchemaType]):
    def __init__(
        self,
        session_maker: async_sessionmaker[SMAsyncSession] | async_sessionmaker[SAAsyncSession],
        user_model: type[UserBase],
        user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
        create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
    ) -> None:
        self._session_maker = session_maker
        self._user_model = user_model
        self._user_schema = user_schema
        self._create_user_schema = create_user_schema

    def _user_query(self):
        return select(self._user_model).options(selectinload(self._user_model.roles))  # type: ignore[arg-type]

    def _to_schema(self, user) -> UserSchemaType:
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

    async def get_user_by_id(self, user_id: UserID) -> UserSchemaType | None:
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchemaType | None:
        return await self.get_user_by_field("email", email)

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        column = getattr(self._user_model, field, None)
        if column is None:
            raise ValueError(f"Model has no field '{field}'")
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(column == value))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def create_user(self, data: CreateUserSchemaType, hashed_password: str) -> UserSchemaType:
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
            user = result.scalars().first()
            assert user is not None  # just committed above
            return self._to_schema(user)

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
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

    async def delete_user(self, user_id: UserID) -> None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            if user:
                await session.delete(user)
                await session.commit()

    async def get_user_roles(self, user_id: UserID) -> list[str]:
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            if user is None:
                return []
            return [r.name for r in user.roles]

    async def get_hashed_password(self, user_id: UserID) -> str | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model.hashed_password).where(self._user_model.id == user_id)
            )
            return result.scalars().first()

    async def set_password(self, user_id: UserID, hashed_password: str) -> None:
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

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenRecord)
                .where(RefreshTokenRecord.user_id == user_id)
                .values(revoked=True)
            )
            await session.commit()

    async def set_user_verified(self, user_id: UserID) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(self._user_model)
                .where(self._user_model.id == user_id)
                .values(is_verified=True)
            )
            await session.commit()

    async def assign_role(self, user_id: UserID, role_name: str) -> None:
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

    async def remove_role(self, user_id: UserID, role_name: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            if user:
                user.roles = [r for r in user.roles if r.name != role_name]
                session.add(user)
                await session.commit()

    # ── Permissions ──────────────────────────────────────────────────

    async def get_role_permissions(self, role_name: str) -> list[str]:
        async with self._session_maker() as session:
            result = await session.execute(
                select(Permission.name)
                .join(RolePermissionLink, Permission.id == RolePermissionLink.permission_id)
                .join(Role, Role.id == RolePermissionLink.role_id)
                .where(Role.name == role_name)
            )
            return list(result.scalars().all())

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        async with self._session_maker() as session:
            # get or create role
            result = await session.execute(select(Role).where(Role.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = Role(name=role_name)
                session.add(role)
                await session.flush()

            # get or create permission
            result = await session.execute(select(Permission).where(Permission.name == permission))
            perm = result.scalars().first()
            if perm is None:
                perm = Permission(name=permission)
                session.add(perm)
                await session.flush()

            # check if link already exists
            result = await session.execute(
                select(RolePermissionLink).where(
                    RolePermissionLink.role_id == role.id,
                    RolePermissionLink.permission_id == perm.id,
                )
            )
            if result.scalars().first() is None:
                session.add(RolePermissionLink(role_id=role.id, permission_id=perm.id))
                await session.commit()

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(select(Role).where(Role.name == role_name))
            role = result.scalars().first()
            if role is None:
                return

            result = await session.execute(select(Permission).where(Permission.name == permission))
            perm = result.scalars().first()
            if perm is None:
                return

            result = await session.execute(
                select(RolePermissionLink).where(
                    RolePermissionLink.role_id == role.id,
                    RolePermissionLink.permission_id == perm.id,
                )
            )
            link = result.scalars().first()
            if link:
                await session.delete(link)
                await session.commit()

    # ── OAuth ────────────────────────────────────────────────────────

    def _to_oauth_account(self, row: OAuthAccountRecord) -> OAuthAccount:
        return OAuthAccount(
            provider=row.provider,
            provider_user_id=row.provider_user_id,
            user_id=row.user_id,
            provider_email=row.provider_email,
            access_token=row.access_token,
            refresh_token=row.refresh_token,
            expires_at=row.expires_at,
        )

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountRecord).where(
                    OAuthAccountRecord.provider == provider,
                    OAuthAccountRecord.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            return self._to_oauth_account(row) if row else None

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountRecord).where(OAuthAccountRecord.user_id == user_id)
            )
            return [self._to_oauth_account(row) for row in result.scalars().all()]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        async with self._session_maker() as session:
            record = OAuthAccountRecord(
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
                update(OAuthAccountRecord)
                .where(
                    OAuthAccountRecord.provider == provider,
                    OAuthAccountRecord.provider_user_id == provider_user_id,
                )
                .values(**data)
            )
            await session.commit()
            return await self.get_oauth_account(provider, provider_user_id)

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountRecord).where(
                    OAuthAccountRecord.provider == provider,
                    OAuthAccountRecord.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            if row:
                await session.delete(row)
                await session.commit()
