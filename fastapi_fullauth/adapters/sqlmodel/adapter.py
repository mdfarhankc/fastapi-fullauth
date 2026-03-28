from __future__ import annotations

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.adapters.sqlmodel.models import RefreshTokenRecord, User
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserSchema


class SQLModelAdapter(AbstractUserAdapter):
    """Async SQLModel adapter for fastapi-fullauth."""

    def __init__(self, session_maker: async_sessionmaker[AsyncSession]) -> None:
        self._session_maker = session_maker

    def _user_query(self):
        return select(User).options(selectinload(User.roles))  # type: ignore[arg-type]

    def _to_schema(self, user: User) -> UserSchema:
        return UserSchema(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_superuser=user.is_superuser,
            roles=[r.name for r in user.roles],
        )

    async def get_user_by_id(self, user_id: str) -> UserSchema | None:
        async with self._session_maker() as session:
            result = await session.execute(
                self._user_query().where(User.id == user_id)
            )
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        async with self._session_maker() as session:
            result = await session.execute(
                self._user_query().where(User.email == email)
            )
            user = result.scalars().first()
            return self._to_schema(user) if user else None

    async def create_user(
        self, data: CreateUserSchema, hashed_password: str
    ) -> UserSchema:
        async with self._session_maker() as session:
            user = User(
                email=data.email,
                hashed_password=hashed_password,
            )
            session.add(user)
            await session.commit()
            # re-fetch with roles loaded
            result = await session.execute(
                self._user_query().where(User.id == user.id)
            )
            user = result.scalars().first()  # type: ignore[assignment]
            return self._to_schema(user)  # type: ignore[arg-type]

    async def update_user(self, user_id: str, data: dict[str, Any]) -> UserSchema:
        async with self._session_maker() as session:
            await session.execute(
                update(User).where(User.id == user_id).values(**data)
            )
            await session.commit()
            result = await session.execute(
                self._user_query().where(User.id == user_id)
            )
            user = result.scalars().first()
            if user is None:
                raise ValueError(f"User {user_id} not found")
            return self._to_schema(user)

    async def delete_user(self, user_id: str) -> None:
        async with self._session_maker() as session:
            result = await session.execute(select(User).where(User.id == user_id))
            user = result.scalars().first()
            if user:
                await session.delete(user)
                await session.commit()

    async def get_user_roles(self, user_id: str) -> list[str]:
        async with self._session_maker() as session:
            result = await session.execute(
                self._user_query().where(User.id == user_id)
            )
            user = result.scalars().first()
            if user is None:
                return []
            return [r.name for r in user.roles]

    async def get_hashed_password(self, user_id: str) -> str | None:
        async with self._session_maker() as session:
            result = await session.execute(
                select(User.hashed_password).where(User.id == user_id)
            )
            return result.scalars().first()

    async def set_password(self, user_id: str, hashed_password: str) -> None:
        async with self._session_maker() as session:
            await session.execute(
                update(User)
                .where(User.id == user_id)
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
                update(User)
                .where(User.id == user_id)
                .values(is_verified=True)
            )
            await session.commit()
