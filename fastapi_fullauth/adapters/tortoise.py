"""Async adapter for Tortoise ORM.

This is a standalone implementation - it does not share the SQLAlchemy base.
Tortoise has its own query API and a contextvar-bound transaction model, so
mirroring the SQL adapter's session plumbing would add more friction than reuse.

Roles and permissions use native Tortoise many-to-many relations, so this
adapter takes no ``user_role_model`` / ``role_permission_model``: declare the
M2M on your ``User`` / ``Role`` models instead (see the model mixins). Name your
concrete models ``User`` / ``Role`` / ``Permission`` and register them under the
Tortoise app label ``models``; the foreign keys and relations resolve them by
that label.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import copy
from datetime import datetime, timezone
from typing import Any, TypeVar

from tortoise.exceptions import IntegrityError
from tortoise.transactions import in_transaction

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    AdapterFeature,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
    SessionAdapterMixin,
)
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.models.tortoise import (
    OAuthAccountMixin,
    PasskeyMixin,
    PermissionMixin,
    RefreshTokenMixin,
    RoleMixin,
    UserMixin,
)
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
    SessionInfo,
    UserID,
    UserSchema,
    UserSchemaType,
)
from fastapi_fullauth.utils import normalize_email

_T = TypeVar("_T")


def _as_aware(dt: datetime) -> datetime:
    """Treat a naive datetime (some drivers drop tzinfo on read) as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class TortoiseAdapter(
    AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    SessionAdapterMixin,
):
    """Tortoise ORM adapter. Implements core auth plus every feature mixin.

    Like the bundled SQL adapters it inherits all mixins statically, so real
    capability comes from which model classes you pass to the constructor; that
    is what ``supports_feature`` reports and what FullAuth uses to decide which
    routers to mount.
    """

    _adapter_name = "TortoiseAdapter"

    # True only on the bound clone yielded by transaction(); guards against
    # nesting and tells the idempotent helpers when a conflict must propagate.
    _in_transaction = False

    def __init__(
        self,
        *,
        user_model: type[UserMixin],
        refresh_token_model: type[RefreshTokenMixin],
        role_model: type[RoleMixin] | None = None,
        permission_model: type[PermissionMixin] | None = None,
        oauth_account_model: type[OAuthAccountMixin] | None = None,
        passkey_model: type[PasskeyMixin] | None = None,
        user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
        create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
        connection_name: str = "default",
    ) -> None:
        if permission_model is not None and role_model is None:
            raise ValueError("Permissions require role_model to also be provided.")
        self._user_model = user_model
        self._refresh_token_model = refresh_token_model
        self._role_model = role_model
        self._permission_model = permission_model
        self._oauth_account_model = oauth_account_model
        self._passkey_model = passkey_model
        self._user_schema = user_schema
        self._create_user_schema = create_user_schema
        self._connection_name = connection_name

    # feature label -> the constructor kwargs that feature needs. Lets _require()
    # name the exact missing argument(s).
    _FEATURE_REQUIRED_KWARGS: dict[str, tuple[str, ...]] = {
        "Role assignment": ("role_model",),
        "Permissions": ("role_model", "permission_model"),
        "OAuth": ("oauth_account_model",),
        "Passkeys": ("passkey_model",),
    }

    def _require(self, model: _T | None, feature: str) -> _T:
        if model is None:
            kwargs = self._FEATURE_REQUIRED_KWARGS.get(feature)
            needed = f" Pass {', '.join(kwargs)}." if kwargs else ""
            raise RuntimeError(
                f"{feature} requires the corresponding model class passed to "
                f"{self._adapter_name}(...).{needed}"
            )
        return model

    def supports_feature(self, feature: AdapterFeature) -> bool:
        return {
            "role": self._role_model is not None,
            "permission": self._permission_model is not None,
            "oauth": self._oauth_account_model is not None,
            "passkey": self._passkey_model is not None,
            "session": True,
        }.get(feature, False)

    # ── Transactions ─────────────────────────────────────────────────

    @asynccontextmanager
    async def transaction(
        self,
    ) -> AsyncIterator["TortoiseAdapter[UserSchemaType, CreateUserSchemaType]"]:
        """Run several adapter calls inside one transaction.

        Tortoise routes the active transaction through a contextvar, so the
        yielded adapter needs no special binding - every adapter call made inside
        the block runs on the transaction's connection and commits or rolls back
        together. Refresh-token rotation relies on this.
        """
        if self._in_transaction:
            raise RuntimeError("transaction() cannot be nested.")
        async with in_transaction(self._connection_name):
            bound = copy(self)
            bound._in_transaction = True
            yield bound

    async def _create(self, model: Any, **kwargs: Any) -> Any:
        """Insert a row, raising IntegrityError on a constraint conflict. Inside a
        transaction the insert runs in a SAVEPOINT so a conflict rolls back only
        this statement and leaves the surrounding transaction usable."""
        if self._in_transaction:
            async with in_transaction(self._connection_name):
                return await model.create(**kwargs)
        return await model.create(**kwargs)

    # ── Users ────────────────────────────────────────────────────────

    async def _to_schema(self, user: Any) -> UserSchemaType:
        data: dict[str, Any] = {}
        for field_name in self._user_schema.model_fields:
            if field_name == "roles":
                continue
            value = getattr(user, field_name, None)
            if value is not None:
                data[field_name] = value
        if "roles" in self._user_schema.model_fields and hasattr(self._user_model, "roles"):
            data["roles"] = [role.name for role in await user.roles.all()]
        return self._user_schema.model_validate(data)

    async def get_user_by_id(self, user_id: UserID) -> UserSchemaType | None:
        user = await self._user_model.get_or_none(id=user_id)
        return await self._to_schema(user) if user else None

    async def get_user_by_email(self, email: str) -> UserSchemaType | None:
        return await self.get_user_by_field("email", normalize_email(email))

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        if field not in self._user_model._meta.fields_map:
            raise ValueError(f"Model has no field '{field}'")
        if field == "email":
            value = normalize_email(value)
        user = await self._user_model.get_or_none(**{field: value})
        return await self._to_schema(user) if user else None

    async def create_user(
        self, data: CreateUserSchemaType, hashed_password: str | None
    ) -> UserSchemaType:
        extra = data.model_dump(exclude={"email", "password"})
        normalized_email = normalize_email(data.email)
        try:
            user = await self._create(
                self._user_model,
                email=normalized_email,
                hashed_password=hashed_password,
                **extra,
            )
        except IntegrityError as e:
            raise UserAlreadyExistsError(
                f"User with email {normalized_email} already exists"
            ) from e
        return await self._to_schema(user)

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
        if "email" in data and data["email"] is not None:
            data = {**data, "email": normalize_email(data["email"])}
        if data:
            await self._user_model.filter(id=user_id).update(**data)
        user = await self._user_model.get_or_none(id=user_id)
        if user is None:
            raise ValueError(f"User {user_id} not found")
        return await self._to_schema(user)

    async def delete_user(self, user_id: UserID) -> None:
        # Tortoise enables FK enforcement and on_delete=CASCADE, so the bulk
        # delete also removes refresh tokens, OAuth/passkey rows, and M2M links.
        await self._user_model.filter(id=user_id).delete()

    async def get_user_roles(self, user_id: UserID) -> list[str]:
        if not hasattr(self._user_model, "roles"):
            return []
        user = await self._user_model.get_or_none(id=user_id)
        if user is None:
            return []
        return [role.name for role in await user.roles.all()]

    async def get_hashed_password(self, user_id: UserID) -> str | None:
        user = await self._user_model.get_or_none(id=user_id)
        return user.hashed_password if user else None

    async def set_password(self, user_id: UserID, hashed_password: str) -> None:
        await self._user_model.filter(id=user_id).update(hashed_password=hashed_password)

    async def set_user_verified(self, user_id: UserID) -> None:
        await self._user_model.filter(id=user_id).update(is_verified=True)

    # ── Refresh tokens ───────────────────────────────────────────────

    async def store_refresh_token(self, token: RefreshToken) -> None:
        await self._refresh_token_model.create(
            token=token.token,
            user_id=token.user_id,
            family_id=token.family_id,
            expires_at=token.expires_at,
            revoked=token.revoked,
            user_agent=token.user_agent,
            ip_address=token.ip_address,
        )

    async def get_refresh_token(self, token_str: str) -> RefreshToken | None:
        row = await self._refresh_token_model.get_or_none(token=token_str)
        if row is None:
            return None
        return RefreshToken(
            token=row.token,
            user_id=row.user_id,
            expires_at=row.expires_at,
            family_id=row.family_id,
            revoked=row.revoked,
            user_agent=row.user_agent,
            ip_address=row.ip_address,
        )

    async def revoke_refresh_token(self, token_str: str) -> bool:
        # Atomic compare-and-swap: only the caller that flips not-revoked ->
        # revoked sees rowcount 1. update() returns the number of matched rows.
        count = await self._refresh_token_model.filter(token=token_str, revoked=False).update(
            revoked=True
        )
        return count == 1

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        await self._refresh_token_model.filter(family_id=family_id).update(revoked=True)

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        await self._refresh_token_model.filter(user_id=user_id).update(revoked=True)

    # ── Sessions ─────────────────────────────────────────────────────

    async def list_user_sessions(self, user_id: UserID) -> list[SessionInfo]:
        model = self._refresh_token_model
        now = datetime.now(timezone.utc)
        rows = await model.filter(user_id=user_id).order_by("created_at")

        # Group every token by family, then keep families with a live token.
        families: dict[str, list[Any]] = {}
        for row in rows:
            families.setdefault(row.family_id, []).append(row)

        sessions: list[SessionInfo] = []
        for family_id, tokens in families.items():
            live = [t for t in tokens if not t.revoked and _as_aware(t.expires_at) > now]
            if not live:
                continue
            newest = max(live, key=lambda t: t.created_at)
            sessions.append(
                SessionInfo(
                    family_id=family_id,
                    ip_address=newest.ip_address,
                    user_agent=newest.user_agent,
                    created_at=_as_aware(min(t.created_at for t in tokens)),
                    last_used_at=_as_aware(max(t.created_at for t in tokens)),
                    expires_at=_as_aware(newest.expires_at),
                )
            )
        sessions.sort(key=lambda s: s.last_used_at, reverse=True)
        return sessions

    async def revoke_user_session(self, user_id: UserID, family_id: str) -> bool:
        # exists(), not update() rowcount: re-revoking an already-revoked family
        # can update 0 rows on some backends, which would wrongly 404 a session
        # the user owns. The contract is idempotent: True if such a family existed.
        if not await self._refresh_token_model.filter(
            user_id=user_id, family_id=family_id
        ).exists():
            return False
        await self._refresh_token_model.filter(user_id=user_id, family_id=family_id).update(
            revoked=True
        )
        return True

    async def revoke_user_sessions_except(self, user_id: UserID, keep_family_id: str) -> int:
        count = (
            await self._refresh_token_model.filter(user_id=user_id, revoked=False)
            .exclude(family_id=keep_family_id)
            .update(revoked=True)
        )
        return int(count)

    # ── Roles ────────────────────────────────────────────────────────

    async def assign_role(self, user_id: UserID, role_name: str) -> None:
        role_model = self._require(self._role_model, "Role assignment")
        role, _ = await role_model.get_or_create(name=role_name)
        user = await self._user_model.get_or_none(id=user_id)
        if user is not None:
            await self._add_relation(user.roles, role)

    async def remove_role(self, user_id: UserID, role_name: str) -> None:
        role_model = self._require(self._role_model, "Role assignment")
        role = await role_model.get_or_none(name=role_name)
        if role is None:
            return
        user = await self._user_model.get_or_none(id=user_id)
        if user is not None:
            await user.roles.remove(role)

    async def _add_relation(self, manager: Any, obj: Any) -> None:
        """Add ``obj`` to a M2M ``manager``, treating a concurrent duplicate
        insert as success on the standalone path (inside a transaction the
        conflict must propagate so it can't poison the surrounding work)."""
        try:
            await manager.add(obj)
        except IntegrityError:
            if self._in_transaction:
                raise

    # ── Permissions ──────────────────────────────────────────────────

    async def get_role_permissions(self, role_name: str) -> list[str]:
        role_model = self._require(self._role_model, "Permissions")
        self._require(self._permission_model, "Permissions")
        role = await role_model.get_or_none(name=role_name)
        if role is None:
            return []
        return [perm.name for perm in await role.permissions.all()]

    async def get_permissions_for_roles(self, role_names: list[str]) -> list[str]:
        self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        names = (
            await permission_model.filter(roles__name__in=role_names)
            .distinct()
            .values_list("name", flat=True)
        )
        return list(set(names))

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role, _ = await role_model.get_or_create(name=role_name)
        perm, _ = await permission_model.get_or_create(name=permission)
        await self._add_relation(role.permissions, perm)

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        permission_model = self._require(self._permission_model, "Permissions")
        role = await role_model.get_or_none(name=role_name)
        if role is None:
            return
        perm = await permission_model.get_or_none(name=permission)
        if perm is None:
            return
        await role.permissions.remove(perm)

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
        row = await oauth_model.get_or_none(provider=provider, provider_user_id=provider_user_id)
        return self._to_oauth_account(row) if row else None

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        rows = await oauth_model.filter(user_id=user_id)
        return [self._to_oauth_account(row) for row in rows]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        try:
            await self._create(
                oauth_model,
                provider=data.provider,
                provider_user_id=data.provider_user_id,
                user_id=data.user_id,
                provider_email=data.provider_email,
                access_token=data.access_token,
                refresh_token=data.refresh_token,
                expires_at=data.expires_at,
            )
        except IntegrityError:
            # Concurrent callback for the same (provider, provider_user_id) won
            # the insert. Return the existing row; both linked the same identity.
            existing = await oauth_model.get_or_none(
                provider=data.provider, provider_user_id=data.provider_user_id
            )
            if existing is not None:
                return self._to_oauth_account(existing)
            raise
        return data

    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        if data:
            await oauth_model.filter(provider=provider, provider_user_id=provider_user_id).update(
                **data
            )
        return await self.get_oauth_account(provider, provider_user_id)

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        await oauth_model.filter(provider=provider, provider_user_id=provider_user_id).delete()

    # ── Passkeys ─────────────────────────────────────────────────────

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
        row = await passkey_model.get_or_none(credential_id=credential_id)
        return self._to_passkey(row) if row else None

    async def get_user_passkeys(self, user_id: UserID) -> list[PasskeyCredential]:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        rows = await passkey_model.filter(user_id=user_id)
        return [self._to_passkey(row) for row in rows]

    async def store_passkey(self, data: PasskeyCredential) -> PasskeyCredential:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        await passkey_model.create(
            id=data.id,
            user_id=data.user_id,
            credential_id=data.credential_id,
            public_key=data.public_key,
            sign_count=data.sign_count,
            device_name=data.device_name,
            transports=",".join(data.transports),
            backed_up=data.backed_up,
        )
        return data

    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> bool:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        now = datetime.now(timezone.utc)
        updated = await passkey_model.filter(
            credential_id=credential_id, sign_count__lt=sign_count
        ).update(sign_count=sign_count, last_used_at=now)
        if updated == 0:
            # Counter did not advance (no-counter authenticator, or a concurrent
            # writer already stored a value >= ours). Touch last_used_at; the
            # caller decides whether to reject based on the new value.
            await passkey_model.filter(credential_id=credential_id).update(last_used_at=now)
            return False
        return True

    async def delete_passkey(self, passkey_id: UserID) -> None:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        await passkey_model.filter(id=passkey_id).delete()
