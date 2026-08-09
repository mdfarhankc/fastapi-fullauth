"""Async adapter for Beanie (MongoDB / ODM on PyMongo's native async driver).

MongoDB has no foreign keys or multi-statement transactions on a standalone
server, so this adapter is shaped around what a single document can guarantee
atomically rather than around joins:

- Roles are an embedded ``roles`` array on the user document; a role's granted
  permissions are an embedded ``permissions`` array on the role document. There
  are no join collections, so the adapter takes no ``user_role_model`` /
  ``role_permission_model``.
- Refresh-token reuse detection is a single-document compare-and-swap
  (``find_one_and_update`` flipping not-revoked -> revoked), which MongoDB
  guarantees atomically - the same guarantee the SQL adapters get from a
  transaction, without needing a replica set. ``transaction()`` therefore stays
  best-effort (the inherited default): the revoke-old / store-new pair in
  rotation is not wrapped in a multi-document transaction, so a crash in the
  microsecond between them orphans at most one refresh token (the user simply
  logs in again); reuse detection itself is unaffected.
- ``delete_user`` removes the related refresh-token / OAuth / passkey documents
  explicitly, since MongoDB will not cascade for us.
"""

from datetime import datetime, timezone
from typing import Any, TypeVar

from pymongo.errors import DuplicateKeyError

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
from fastapi_fullauth.models.beanie import (
    OAuthAccountDocument,
    PasskeyDocument,
    PermissionDocument,
    RefreshTokenDocument,
    RoleDocument,
    UserDocument,
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
    """Treat a naive datetime (the driver can drop tzinfo on read) as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class BeanieAdapter(
    AbstractUserAdapter[UserSchemaType, CreateUserSchemaType],
    RoleAdapterMixin,
    PermissionAdapterMixin,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    SessionAdapterMixin,
):
    """Beanie (MongoDB) adapter. Implements core auth plus every feature mixin.

    Like the bundled SQL adapters it inherits all mixins statically, so real
    capability comes from which document classes you pass to the constructor;
    that is what ``supports_feature`` reports and what FullAuth uses to decide
    which routers to mount. Register every document you pass here with Beanie at
    startup via ``init_beanie(document_models=[...])``.
    """

    _adapter_name = "BeanieAdapter"

    def __init__(
        self,
        *,
        user_model: type[UserDocument],
        refresh_token_model: type[RefreshTokenDocument],
        role_model: type[RoleDocument] | None = None,
        permission_model: type[PermissionDocument] | None = None,
        oauth_account_model: type[OAuthAccountDocument] | None = None,
        passkey_model: type[PasskeyDocument] | None = None,
        user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
        create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
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
        self.validate_user_id_type()

    def model_user_id_type(self) -> Any | None:
        field = self._user_model.model_fields.get("id")
        return None if field is None else field.annotation

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
                f"{feature} requires the corresponding document class passed to "
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

    # ── Users ────────────────────────────────────────────────────────

    def _to_schema(self, doc: Any) -> UserSchemaType:
        data: dict[str, Any] = {}
        for field_name in self._user_schema.model_fields:
            if field_name == "roles":
                continue
            value = getattr(doc, field_name, None)
            if value is not None:
                data[field_name] = value
        if "roles" in self._user_schema.model_fields:
            data["roles"] = list(getattr(doc, "roles", []) or [])
        return self._user_schema.model_validate(data)

    async def get_user_by_id(self, user_id: UserID) -> UserSchemaType | None:
        doc = await self._user_model.get(user_id)
        return self._to_schema(doc) if doc else None

    async def get_user_by_email(self, email: str) -> UserSchemaType | None:
        return await self.get_user_by_field("email", normalize_email(email))

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        if field not in self._user_model.model_fields:
            raise ValueError(f"Model has no field '{field}'")
        if field == "email":
            value = normalize_email(value)
        doc = await self._user_model.find_one({field: value})
        return self._to_schema(doc) if doc else None

    async def create_user(
        self, data: CreateUserSchemaType, hashed_password: str | None
    ) -> UserSchemaType:
        extra = data.model_dump(exclude={"email", "password"})
        normalized_email = normalize_email(data.email)
        doc = self._user_model(
            email=normalized_email,
            hashed_password=hashed_password,
            **extra,
        )
        try:
            await doc.insert()
        except DuplicateKeyError as e:
            raise UserAlreadyExistsError(
                f"User with email {normalized_email} already exists"
            ) from e
        return self._to_schema(doc)

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
        doc = await self._user_model.get(user_id)
        if doc is None:
            raise ValueError(f"User {user_id} not found")
        if data:
            if "email" in data and data["email"] is not None:
                data = {**data, "email": normalize_email(data["email"])}
            await doc.update({"$set": data})
            doc = await self._user_model.get(user_id)
        return self._to_schema(doc)

    async def delete_user(self, user_id: UserID) -> None:
        # MongoDB has no FK cascade, so remove the dependent documents by hand.
        # Roles live in the embedded array and go with the user document.
        doc = await self._user_model.get(user_id)
        if doc is not None:
            await doc.delete()
        await self._refresh_token_model.find(self._refresh_token_model.user_id == user_id).delete()
        if self._oauth_account_model is not None:
            await self._oauth_account_model.find(
                self._oauth_account_model.user_id == user_id
            ).delete()
        if self._passkey_model is not None:
            await self._passkey_model.find(self._passkey_model.user_id == user_id).delete()

    async def get_user_roles(self, user_id: UserID) -> list[str]:
        doc = await self._user_model.get(user_id)
        if doc is None:
            return []
        return list(getattr(doc, "roles", []) or [])

    async def get_hashed_password(self, user_id: UserID) -> str | None:
        doc = await self._user_model.get(user_id)
        return doc.hashed_password if doc else None

    async def set_password(self, user_id: UserID, hashed_password: str) -> None:
        doc = await self._user_model.get(user_id)
        if doc is not None:
            await doc.update({"$set": {"hashed_password": hashed_password}})

    async def set_user_verified(self, user_id: UserID) -> None:
        doc = await self._user_model.get(user_id)
        if doc is not None:
            await doc.update({"$set": {"is_verified": True}})

    # ── Refresh tokens ───────────────────────────────────────────────

    async def store_refresh_token(self, token: RefreshToken) -> None:
        await self._refresh_token_model(
            token=token.token,
            user_id=token.user_id,
            family_id=token.family_id,
            expires_at=token.expires_at,
            revoked=token.revoked,
            user_agent=token.user_agent,
            ip_address=token.ip_address,
        ).insert()

    async def get_refresh_token(self, token_str: str) -> RefreshToken | None:
        doc = await self._refresh_token_model.find_one(self._refresh_token_model.token == token_str)
        if doc is None:
            return None
        return RefreshToken(
            token=doc.token,
            user_id=doc.user_id,
            expires_at=doc.expires_at,
            family_id=doc.family_id,
            revoked=doc.revoked,
            user_agent=doc.user_agent,
            ip_address=doc.ip_address,
        )

    async def revoke_refresh_token(self, token_str: str) -> bool:
        # Atomic compare-and-swap on a single document: only the caller that flips
        # not-revoked -> revoked gets the pre-image back; a missing or
        # already-revoked token returns None. This is the reuse/concurrent-use
        # signal, and MongoDB guarantees it without a transaction.
        coll = self._refresh_token_model.get_pymongo_collection()
        result = await coll.find_one_and_update(
            {"token": token_str, "revoked": False},
            {"$set": {"revoked": True}},
        )
        return result is not None

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        await self._refresh_token_model.find(
            self._refresh_token_model.family_id == family_id
        ).update({"$set": {"revoked": True}})

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        await self._refresh_token_model.find(self._refresh_token_model.user_id == user_id).update(
            {"$set": {"revoked": True}}
        )

    # ── Sessions ─────────────────────────────────────────────────────

    async def list_user_sessions(self, user_id: UserID) -> list[SessionInfo]:
        model = self._refresh_token_model
        now = datetime.now(timezone.utc)
        rows = await model.find(model.user_id == user_id).to_list()

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
        # Existence check, not the update count: re-revoking an already-revoked
        # family modifies 0 documents, which would wrongly 404 a session the user
        # owns. The contract is idempotent: True if such a family existed.
        model = self._refresh_token_model
        exists = await model.find_one(model.user_id == user_id, model.family_id == family_id)
        if exists is None:
            return False
        await model.find(model.user_id == user_id, model.family_id == family_id).update(
            {"$set": {"revoked": True}}
        )
        return True

    async def revoke_user_sessions_except(self, user_id: UserID, keep_family_id: str) -> int:
        model = self._refresh_token_model
        result = await model.find(
            model.user_id == user_id,
            model.revoked == False,  # noqa: E712 - Beanie builds a query, not a bool
            model.family_id != keep_family_id,
        ).update({"$set": {"revoked": True}})
        return int(result.modified_count)

    # ── Roles ────────────────────────────────────────────────────────

    async def _get_or_create_role(self, name: str) -> Any:
        role_model = self._require(self._role_model, "Role assignment")
        existing = await role_model.find_one(role_model.name == name)
        if existing is not None:
            return existing
        try:
            doc = role_model(name=name)
            await doc.insert()
            return doc
        except DuplicateKeyError:
            return await role_model.find_one(role_model.name == name)

    async def assign_role(self, user_id: UserID, role_name: str) -> None:
        self._require(self._role_model, "Role assignment")
        await self._get_or_create_role(role_name)
        # $addToSet is idempotent: re-assigning an existing role is a no-op.
        await self._user_model.find_one(self._user_model.id == user_id).update(
            {"$addToSet": {"roles": role_name}}
        )

    async def remove_role(self, user_id: UserID, role_name: str) -> None:
        self._require(self._role_model, "Role assignment")
        await self._user_model.find_one(self._user_model.id == user_id).update(
            {"$pull": {"roles": role_name}}
        )

    # ── Permissions ──────────────────────────────────────────────────

    async def _get_or_create_permission(self, name: str) -> Any:
        permission_model = self._require(self._permission_model, "Permissions")
        existing = await permission_model.find_one(permission_model.name == name)
        if existing is not None:
            return existing
        try:
            doc = permission_model(name=name)
            await doc.insert()
            return doc
        except DuplicateKeyError:
            return await permission_model.find_one(permission_model.name == name)

    async def get_role_permissions(self, role_name: str) -> list[str]:
        role_model = self._require(self._role_model, "Permissions")
        self._require(self._permission_model, "Permissions")
        role = await role_model.find_one(role_model.name == role_name)
        if role is None:
            return []
        return list(role.permissions)

    async def get_permissions_for_roles(self, role_names: list[str]) -> list[str]:
        role_model = self._require(self._role_model, "Permissions")
        self._require(self._permission_model, "Permissions")
        rows = await role_model.find({"name": {"$in": role_names}}).to_list()
        perms: set[str] = {p for r in rows for p in r.permissions}
        return list(perms)

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        self._require(self._permission_model, "Permissions")
        await self._get_or_create_role(role_name)
        await self._get_or_create_permission(permission)
        # The embedded array on the role is the authoritative grant; the catalog
        # document records the permission name. $addToSet keeps the array unique.
        await role_model.find_one(role_model.name == role_name).update(
            {"$addToSet": {"permissions": permission}}
        )

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        role_model = self._require(self._role_model, "Permissions")
        self._require(self._permission_model, "Permissions")
        role = await role_model.find_one(role_model.name == role_name)
        if role is None:
            return
        await role_model.find_one(role_model.name == role_name).update(
            {"$pull": {"permissions": permission}}
        )

    # ── OAuth ────────────────────────────────────────────────────────

    def _to_oauth_account(self, doc: Any) -> OAuthAccount:
        return OAuthAccount(
            provider=doc.provider,
            provider_user_id=doc.provider_user_id,
            user_id=doc.user_id,
            provider_email=doc.provider_email,
            access_token=doc.access_token,
            refresh_token=doc.refresh_token,
            expires_at=doc.expires_at,
        )

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        doc = await oauth_model.find_one(
            oauth_model.provider == provider,
            oauth_model.provider_user_id == provider_user_id,
        )
        return self._to_oauth_account(doc) if doc else None

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        rows = await oauth_model.find(oauth_model.user_id == user_id).to_list()
        return [self._to_oauth_account(row) for row in rows]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        doc = oauth_model(
            provider=data.provider,
            provider_user_id=data.provider_user_id,
            user_id=data.user_id,
            provider_email=data.provider_email,
            access_token=data.access_token,
            refresh_token=data.refresh_token,
            expires_at=data.expires_at,
        )
        try:
            await doc.insert()
        except DuplicateKeyError:
            # Concurrent callback for the same (provider, provider_user_id) won
            # the insert. Return the existing account; both linked the same identity.
            existing = await oauth_model.find_one(
                oauth_model.provider == data.provider,
                oauth_model.provider_user_id == data.provider_user_id,
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
            await oauth_model.find_one(
                oauth_model.provider == provider,
                oauth_model.provider_user_id == provider_user_id,
            ).update({"$set": data})
        return await self.get_oauth_account(provider, provider_user_id)

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        oauth_model = self._require(self._oauth_account_model, "OAuth")
        await oauth_model.find(
            oauth_model.provider == provider,
            oauth_model.provider_user_id == provider_user_id,
        ).delete()

    # ── Passkeys ─────────────────────────────────────────────────────

    def _to_passkey(self, doc: Any) -> PasskeyCredential:
        return PasskeyCredential(
            id=doc.id,
            user_id=doc.user_id,
            credential_id=doc.credential_id,
            public_key=doc.public_key,
            sign_count=doc.sign_count,
            device_name=doc.device_name,
            transports=list(doc.transports),
            backed_up=doc.backed_up,
            created_at=doc.created_at,
            last_used_at=doc.last_used_at,
        )

    async def get_passkey_by_credential_id(self, credential_id: str) -> PasskeyCredential | None:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        doc = await passkey_model.find_one(passkey_model.credential_id == credential_id)
        return self._to_passkey(doc) if doc else None

    async def get_user_passkeys(self, user_id: UserID) -> list[PasskeyCredential]:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        rows = await passkey_model.find(passkey_model.user_id == user_id).to_list()
        return [self._to_passkey(row) for row in rows]

    async def store_passkey(self, data: PasskeyCredential) -> PasskeyCredential:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        await passkey_model(
            id=data.id,
            user_id=data.user_id,
            credential_id=data.credential_id,
            public_key=data.public_key,
            sign_count=data.sign_count,
            device_name=data.device_name,
            transports=list(data.transports),
            backed_up=data.backed_up,
        ).insert()
        return data

    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> bool:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        now = datetime.now(timezone.utc)
        coll = passkey_model.get_pymongo_collection()
        # Conditional single-document update: only advances when the new value is
        # strictly greater, keyed on the string credential_id (no UUID encoding).
        result = await coll.update_one(
            {"credential_id": credential_id, "sign_count": {"$lt": sign_count}},
            {"$set": {"sign_count": sign_count, "last_used_at": now}},
        )
        if result.modified_count == 0:
            # Counter did not advance (no-counter authenticator, or a concurrent
            # writer already stored a value >= ours). Touch last_used_at; the
            # caller decides whether to reject based on the new value.
            await coll.update_one({"credential_id": credential_id}, {"$set": {"last_used_at": now}})
            return False
        return True

    async def delete_passkey(self, passkey_id: UserID) -> None:
        passkey_model = self._require(self._passkey_model, "Passkeys")
        doc = await passkey_model.get(passkey_id)
        if doc is not None:
            await doc.delete()
