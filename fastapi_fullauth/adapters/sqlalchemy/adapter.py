from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
)
from fastapi_fullauth.adapters.sqlalchemy.models.base import RefreshTokenModel, UserBase
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
    UserID,
    UserSchema,
    UserSchemaType,
)


class SQLAlchemyAdapter(
    AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
):
    def __init__(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        user_model: type[UserBase],
        user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
        create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
    ) -> None:
        self._session_maker = session_maker
        self._user_model = user_model
        self._user_schema = user_schema
        self._create_user_schema = create_user_schema

    def _to_schema(self, user) -> UserSchemaType:
        data = {}
        for field_name in self._user_schema.model_fields:
            val = getattr(user, field_name, None)
            if val is not None:
                data[field_name] = val
        if hasattr(user, "roles"):
            data["roles"] = [r.name for r in user.roles]
        return self._user_schema.model_validate(data)

    async def get_user_by_id(self, user_id: UserID) -> UserSchemaType | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchemaType | None:
        return await self.get_user_by_field("email", email)

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        column = getattr(self._user_model, field, None)
        if column is None:
            raise ValueError(f"Model has no field '{field}'")
        async with self._session_maker() as session:
            result = await session.execute(select(self._user_model).where(column == value))
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
            try:
                await session.commit()
            except IntegrityError as e:
                await session.rollback()
                raise UserAlreadyExistsError(f"User with email {data.email} already exists") from e
            await session.refresh(user)
            return self._to_schema(user)

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
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
        if not hasattr(self._user_model, "roles"):
            return []
        async with self._session_maker() as session:
            result = await session.execute(
                select(self._user_model).where(self._user_model.id == user_id)
            )
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

    async def revoke_refresh_token(self, token_str: str) -> bool:
        async with self._session_maker() as session:
            result = await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.token == token_str)
                .where(RefreshTokenModel.revoked.is_(False))
                .values(revoked=True)
            )
            await session.commit()
            return result.rowcount == 1

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.family_id == family_id)
                .values(revoked=True)
            )
            await session.commit()

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(RefreshTokenModel)
                .where(RefreshTokenModel.user_id == user_id)
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
        from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

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

    async def remove_role(self, user_id: UserID, role_name: str) -> None:
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

    # ── Permissions ──────────────────────────────────────────────────

    async def get_permissions_for_roles(self, role_names: list[str]) -> list[str]:
        from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
            PermissionModel,
            RolePermissionModel,
        )
        from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(PermissionModel.name)
                .join(
                    RolePermissionModel,
                    PermissionModel.id == RolePermissionModel.permission_id,
                )
                .join(RoleModel, RoleModel.id == RolePermissionModel.role_id)
                .where(RoleModel.name.in_(role_names))
            )
            return list(set(result.scalars().all()))

    async def get_role_permissions(self, role_name: str) -> list[str]:
        from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
            PermissionModel,
            RolePermissionModel,
        )
        from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(PermissionModel.name)
                .join(
                    RolePermissionModel,
                    PermissionModel.id == RolePermissionModel.permission_id,
                )
                .join(RoleModel, RoleModel.id == RolePermissionModel.role_id)
                .where(RoleModel.name == role_name)
            )
            return list(result.scalars().all())

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
            PermissionModel,
            RolePermissionModel,
        )
        from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

        async with self._session_maker() as session:
            result = await session.execute(select(RoleModel).where(RoleModel.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = RoleModel(name=role_name)
                session.add(role)
                await session.flush()

            result = await session.execute(
                select(PermissionModel).where(PermissionModel.name == permission)
            )
            perm = result.scalars().first()
            if perm is None:
                perm = PermissionModel(name=permission)
                session.add(perm)
                await session.flush()

            result = await session.execute(
                select(RolePermissionModel).where(
                    RolePermissionModel.role_id == role.id,
                    RolePermissionModel.permission_id == perm.id,
                )
            )
            if result.scalars().first() is None:
                session.add(RolePermissionModel(role_id=role.id, permission_id=perm.id))
                await session.commit()

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        from fastapi_fullauth.adapters.sqlalchemy.models.permission import (
            PermissionModel,
            RolePermissionModel,
        )
        from fastapi_fullauth.adapters.sqlalchemy.models.role import RoleModel

        async with self._session_maker() as session:
            result = await session.execute(select(RoleModel).where(RoleModel.name == role_name))
            role = result.scalars().first()
            if role is None:
                return

            result = await session.execute(
                select(PermissionModel).where(PermissionModel.name == permission)
            )
            perm = result.scalars().first()
            if perm is None:
                return

            result = await session.execute(
                select(RolePermissionModel).where(
                    RolePermissionModel.role_id == role.id,
                    RolePermissionModel.permission_id == perm.id,
                )
            )
            link = result.scalars().first()
            if link:
                await session.delete(link)
                await session.commit()

    # ── OAuth ────────────────────────────────────────────────────────

    def _to_oauth_account(self, row) -> OAuthAccount:
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
        from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountModel).where(
                    OAuthAccountModel.provider == provider,
                    OAuthAccountModel.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            return self._to_oauth_account(row) if row else None

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(OAuthAccountModel).where(OAuthAccountModel.user_id == user_id)
            )
            return [self._to_oauth_account(row) for row in result.scalars().all()]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

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
            try:
                await session.commit()
            except IntegrityError:
                # Concurrent OAuth callback for the same (provider, provider_user_id)
                # won the insert. Return the existing row — both callers linked the
                # same identity, which is the intended outcome.
                await session.rollback()
                result = await session.execute(
                    select(OAuthAccountModel).where(
                        OAuthAccountModel.provider == data.provider,
                        OAuthAccountModel.provider_user_id == data.provider_user_id,
                    )
                )
                existing = result.scalars().first()
                if existing is not None:
                    return self._to_oauth_account(existing)
                raise
            return data

    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None:
        from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

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
        from fastapi_fullauth.adapters.sqlalchemy.models.oauth import OAuthAccountModel

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

    # ── Passkeys ────────────────────────────────────────────────────

    def _to_passkey(self, row) -> PasskeyCredential:
        return PasskeyCredential(
            id=row.id,
            user_id=row.user_id,
            credential_id=row.credential_id,
            public_key=row.public_key,
            sign_count=row.sign_count,
            device_name=row.device_name,
            transports=row.transports.split(",") if row.transports else [],
            backed_up=row.backed_up,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
        )

    async def get_passkey_by_credential_id(self, credential_id: str) -> PasskeyCredential | None:
        from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(PasskeyModel).where(PasskeyModel.credential_id == credential_id)
            )
            row = result.scalars().first()
            return self._to_passkey(row) if row else None

    async def get_user_passkeys(self, user_id: UserID) -> list[PasskeyCredential]:
        from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(PasskeyModel).where(PasskeyModel.user_id == user_id)
            )
            return [self._to_passkey(row) for row in result.scalars().all()]

    async def store_passkey(self, data: PasskeyCredential) -> PasskeyCredential:
        from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel

        async with self._session_maker() as session:
            record = PasskeyModel(
                id=data.id,
                user_id=data.user_id,
                credential_id=data.credential_id,
                public_key=data.public_key,
                sign_count=data.sign_count,
                device_name=data.device_name,
                transports=",".join(data.transports),
                backed_up=data.backed_up,
            )
            session.add(record)
            await session.commit()
            return data

    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> bool:
        from datetime import datetime, timezone

        from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel

        now = datetime.now(timezone.utc)
        async with self._session_maker() as session:
            result = await session.execute(
                update(PasskeyModel)
                .where(PasskeyModel.credential_id == credential_id)
                .where(PasskeyModel.sign_count < sign_count)
                .values(sign_count=sign_count, last_used_at=now)
            )
            if result.rowcount == 0:
                # Counter did not advance. Either the authenticator doesn't maintain a
                # counter (both stored and new are 0) or a concurrent writer already wrote
                # a value ≥ ours. Touch last_used_at for the no-counter case; caller
                # decides whether to reject based on the new_sign_count value.
                await session.execute(
                    update(PasskeyModel)
                    .where(PasskeyModel.credential_id == credential_id)
                    .values(last_used_at=now)
                )
                await session.commit()
                return False
            await session.commit()
            return True

    async def delete_passkey(self, passkey_id: UserID) -> None:
        from fastapi_fullauth.adapters.sqlalchemy.models.passkey import PasskeyModel

        async with self._session_maker() as session:
            result = await session.execute(
                select(PasskeyModel).where(PasskeyModel.id == passkey_id)
            )
            row = result.scalars().first()
            if row:
                await session.delete(row)
                await session.commit()
