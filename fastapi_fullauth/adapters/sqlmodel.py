from datetime import datetime, timezone
from typing import Any, TypeVar

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession as SAAsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlmodel.ext.asyncio.session import AsyncSession as SMAsyncSession

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
)
from fastapi_fullauth.exceptions import UserAlreadyExistsError
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
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
    UserID,
    UserSchema,
    UserSchemaType,
)
from fastapi_fullauth.utils import normalize_email

_T = TypeVar("_T")


class SQLModelAdapter(
    AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
):
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
        if (role_model is None) != (user_role_model is None):
            raise ValueError("role_model and user_role_model must be provided together.")
        if (permission_model is None) != (role_permission_model is None):
            raise ValueError(
                "permission_model and role_permission_model must be provided together."
            )
        if permission_model is not None and role_model is None:
            raise ValueError(
                "Permissions require role_model and user_role_model to also be provided."
            )

        self._session_maker = session_maker
        self._user_model = user_model
        self._refresh_token_model = refresh_token_model
        self._role_model = role_model
        self._user_role_model = user_role_model
        self._permission_model = permission_model
        self._role_permission_model = role_permission_model
        self._oauth_account_model = oauth_account_model
        self._passkey_model = passkey_model
        self._user_schema = user_schema
        self._create_user_schema = create_user_schema

    def _require(self, model: _T | None, feature: str) -> _T:
        if model is None:
            raise RuntimeError(
                f"{feature} requires the corresponding model class passed to SQLModelAdapter(...)."
            )
        return model

    def _user_query(self) -> Any:
        query = select(self._user_model)
        if hasattr(self._user_model, "roles"):
            query = query.options(selectinload(self._user_model.roles))
        return query

    def _to_schema(self, user: Any) -> UserSchemaType:
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
            result = await session.execute(self._user_query().where(self._user_model.id == user_id))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchemaType | None:
        return await self.get_user_by_field("email", normalize_email(email))

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        column = getattr(self._user_model, field, None)
        if column is None:
            raise ValueError(f"Model has no field '{field}'")
        if field == "email":
            value = normalize_email(value)
        async with self._session_maker() as session:
            result = await session.execute(self._user_query().where(column == value))
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def create_user(
        self, data: CreateUserSchemaType, hashed_password: str | None
    ) -> UserSchemaType:
        async with self._session_maker() as session:
            extra = data.model_dump(exclude={"email", "password"})
            email = normalize_email(data.email)
            user = self._user_model(
                email=email,
                hashed_password=hashed_password,
                **extra,
            )
            session.add(user)
            try:
                await session.commit()
            except IntegrityError as e:
                await session.rollback()
                raise UserAlreadyExistsError(f"User with email {email} already exists") from e
            # re-fetch with roles loaded
            result = await session.execute(self._user_query().where(self._user_model.id == user.id))
            user = result.scalars().first()
            assert user is not None  # just committed above
            return self._to_schema(user)

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
        if "email" in data and data["email"] is not None:
            data = {**data, "email": normalize_email(data["email"])}
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
        if not hasattr(self._user_model, "roles"):
            return []
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
            db_token = self._refresh_token_model(
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
                select(self._refresh_token_model).where(
                    self._refresh_token_model.token == token_str
                )
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
                update(self._refresh_token_model)
                .where(self._refresh_token_model.token == token_str)
                .where(self._refresh_token_model.revoked.is_(False))
                .values(revoked=True)
            )
            await session.commit()
            return result.rowcount == 1

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(self._refresh_token_model)
                .where(self._refresh_token_model.family_id == family_id)
                .values(revoked=True)
            )
            await session.commit()

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(self._refresh_token_model)
                .where(self._refresh_token_model.user_id == user_id)
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
        role_model = self._require(self._role_model, "Role assignment")

        async with self._session_maker() as session:
            result = await session.execute(select(role_model).where(role_model.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = role_model(name=role_name)
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

    async def get_permissions_for_roles(self, role_names: list[str]) -> list[str]:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role_permission_model = self._require(self._role_permission_model, "Permissions")

        async with self._session_maker() as session:
            result = await session.execute(
                select(permission_model.name)
                .join(
                    role_permission_model,
                    permission_model.id == role_permission_model.permission_id,
                )
                .join(role_model, role_model.id == role_permission_model.role_id)
                .where(role_model.name.in_(role_names))
            )
            return list(set(result.scalars().all()))

    async def get_role_permissions(self, role_name: str) -> list[str]:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role_permission_model = self._require(self._role_permission_model, "Permissions")

        async with self._session_maker() as session:
            result = await session.execute(
                select(permission_model.name)
                .join(
                    role_permission_model,
                    permission_model.id == role_permission_model.permission_id,
                )
                .join(role_model, role_model.id == role_permission_model.role_id)
                .where(role_model.name == role_name)
            )
            return list(result.scalars().all())

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role_permission_model = self._require(self._role_permission_model, "Permissions")

        async with self._session_maker() as session:
            result = await session.execute(select(role_model).where(role_model.name == role_name))
            role = result.scalars().first()
            if role is None:
                role = role_model(name=role_name)
                session.add(role)
                await session.flush()

            result = await session.execute(
                select(permission_model).where(permission_model.name == permission)
            )
            perm = result.scalars().first()
            if perm is None:
                perm = permission_model(name=permission)
                session.add(perm)
                await session.flush()

            result = await session.execute(
                select(role_permission_model).where(
                    role_permission_model.role_id == role.id,
                    role_permission_model.permission_id == perm.id,
                )
            )
            if result.scalars().first() is None:
                session.add(role_permission_model(role_id=role.id, permission_id=perm.id))
                await session.commit()

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role_permission_model = self._require(self._role_permission_model, "Permissions")

        async with self._session_maker() as session:
            result = await session.execute(select(role_model).where(role_model.name == role_name))
            role = result.scalars().first()
            if role is None:
                return

            result = await session.execute(
                select(permission_model).where(permission_model.name == permission)
            )
            perm = result.scalars().first()
            if perm is None:
                return

            result = await session.execute(
                select(role_permission_model).where(
                    role_permission_model.role_id == role.id,
                    role_permission_model.permission_id == perm.id,
                )
            )
            link = result.scalars().first()
            if link:
                await session.delete(link)
                await session.commit()

    # ── OAuth ────────────────────────────────────────────────────────

    def _to_oauth_account(self, row: Any) -> OAuthAccount:
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
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        async with self._session_maker() as session:
            result = await session.execute(
                select(oauth_model).where(
                    oauth_model.provider == provider,
                    oauth_model.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            return self._to_oauth_account(row) if row else None

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        async with self._session_maker() as session:
            result = await session.execute(
                select(oauth_model).where(oauth_model.user_id == user_id)
            )
            return [self._to_oauth_account(row) for row in result.scalars().all()]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        async with self._session_maker() as session:
            record = oauth_model(
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
                # won the insert. Return the existing row.
                await session.rollback()
                result = await session.execute(
                    select(oauth_model).where(
                        oauth_model.provider == data.provider,
                        oauth_model.provider_user_id == data.provider_user_id,
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
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        async with self._session_maker() as session:
            await session.execute(
                update(oauth_model)
                .where(
                    oauth_model.provider == provider,
                    oauth_model.provider_user_id == provider_user_id,
                )
                .values(**data)
            )
            await session.commit()
            return await self.get_oauth_account(provider, provider_user_id)

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        async with self._session_maker() as session:
            result = await session.execute(
                select(oauth_model).where(
                    oauth_model.provider == provider,
                    oauth_model.provider_user_id == provider_user_id,
                )
            )
            row = result.scalars().first()
            if row:
                await session.delete(row)
                await session.commit()

    # ── Passkeys ────────────────────────────────────────────────────

    def _to_passkey(self, row: Any) -> PasskeyCredential:
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
        passkey_model = self._require(self._passkey_model, "Passkeys")
        async with self._session_maker() as session:
            result = await session.execute(
                select(passkey_model).where(passkey_model.credential_id == credential_id)
            )
            row = result.scalars().first()
            return self._to_passkey(row) if row else None

    async def get_user_passkeys(self, user_id: UserID) -> list[PasskeyCredential]:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        async with self._session_maker() as session:
            result = await session.execute(
                select(passkey_model).where(passkey_model.user_id == user_id)
            )
            return [self._to_passkey(row) for row in result.scalars().all()]

    async def store_passkey(self, data: PasskeyCredential) -> PasskeyCredential:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        async with self._session_maker() as session:
            record = passkey_model(
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
        passkey_model = self._require(self._passkey_model, "Passkeys")
        now = datetime.now(timezone.utc)
        async with self._session_maker() as session:
            result = await session.execute(
                update(passkey_model)
                .where(passkey_model.credential_id == credential_id)
                .where(passkey_model.sign_count < sign_count)
                .values(sign_count=sign_count, last_used_at=now)
            )
            if result.rowcount == 0:
                await session.execute(
                    update(passkey_model)
                    .where(passkey_model.credential_id == credential_id)
                    .values(last_used_at=now)
                )
                await session.commit()
                return False
            await session.commit()
            return True

    async def delete_passkey(self, passkey_id: UserID) -> None:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        async with self._session_maker() as session:
            result = await session.execute(
                select(passkey_model).where(passkey_model.id == passkey_id)
            )
            row = result.scalars().first()
            if row:
                await session.delete(row)
                await session.commit()
