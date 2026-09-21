from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from functools import cache
from types import UnionType
from typing import Any, Generic, Literal, Protocol, TypeVar, Union, cast, get_args, get_origin
from uuid import UUID

from pydantic import BaseModel, TypeAdapter

from fastapi_fullauth.types import (
    CreateUserSchemaType,
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
    SessionInfo,
    UserID,
    UserSchemaType,
)

AdapterFeature = Literal["role", "permission", "oauth", "passkey", "session"]

# Columns only the library may set when creating a user. A CreateUserSchema that
# exposes them would otherwise let a registering client grant itself admin,
# pre-verify its email, attach roles, or supply its own password hash.
PRIVILEGED_USER_FIELDS = frozenset(
    {"id", "hashed_password", "is_active", "is_verified", "is_superuser", "roles"}
)


def create_user_extra_fields(data: BaseModel) -> dict[str, Any]:
    """The app-specific fields of a create schema that adapters may persist.

    Drops ``email`` and ``password`` (handled explicitly) and
    ``PRIVILEGED_USER_FIELDS``. Custom adapters should build ``create_user``
    kwargs from this rather than dumping the schema directly.
    """
    return data.model_dump(exclude={"email", "password", *PRIVILEGED_USER_FIELDS})


@cache
def _id_type_adapter(annotation: Any) -> TypeAdapter[Any]:
    """Validator for a user id type, cached because it is built per request."""
    return TypeAdapter(annotation)


def _type_name(annotation: Any) -> str:
    return annotation.__name__ if isinstance(annotation, type) else str(annotation)


def _without_none(annotation: Any) -> Any:
    """``X | None`` -> ``X``. Optional keys are common (``id: int | None`` on
    SQLModel and Beanie models) and store the same type as ``X``."""
    if get_origin(annotation) not in (Union, UnionType):
        return annotation
    members = [arg for arg in get_args(annotation) if arg is not type(None)]
    return members[0] if len(members) == 1 else annotation


def _key_types_match(first: Any, second: Any) -> bool:
    if first is second:
        return True
    return (
        isinstance(first, type)
        and isinstance(second, type)
        and (issubclass(first, second) or issubclass(second, first))
    )


class _SupportsUserRoles(Protocol):
    """The contract PermissionAdapterMixin relies on from its co-mixins.

    AbstractUserAdapter provides a default get_user_roles, and RoleAdapterMixin
    declares it abstract; a permission adapter is always combined with one of
    them. This Protocol lets get_user_permissions call it without a type: ignore.
    """

    async def get_user_roles(self, user_id: UserID) -> list[str]: ...


class AbstractUserAdapter(ABC, Generic[UserSchemaType, CreateUserSchemaType]):
    """Core adapter interface. Implement this for your ORM/database.

    Provides user CRUD, passwords, refresh tokens, and verification.
    For roles, permissions, or OAuth, also inherit the corresponding mixin.
    """

    _user_schema: type[UserSchemaType]
    _create_user_schema: type[CreateUserSchemaType]

    @abstractmethod
    async def get_user_by_id(self, user_id: UserID) -> UserSchemaType | None: ...

    @abstractmethod
    async def get_user_by_email(self, email: str) -> UserSchemaType | None: ...

    async def get_user_by_field(self, field: str, value: str) -> UserSchemaType | None:
        """Look up a user by an arbitrary field. Override for non-email login."""
        if field == "email":
            return await self.get_user_by_email(value)
        raise NotImplementedError(
            f"Lookup by '{field}' not implemented; override get_user_by_field()"
        )

    @abstractmethod
    async def create_user(
        self, data: CreateUserSchemaType, hashed_password: str | None
    ) -> UserSchemaType: ...

    @abstractmethod
    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType:
        """Apply ``data`` to the user row.

        WARNING: this writes ``data`` verbatim and performs no field filtering -
        it can set privileged columns (``is_superuser``, ``is_verified``,
        ``hashed_password``). The profile route filters request input through
        ``validate_profile_updates`` (``PROTECTED_FIELDS``) before calling this.
        Never pass an unfiltered request body straight to ``update_user``.
        """
        ...

    @abstractmethod
    async def delete_user(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def get_hashed_password(self, user_id: UserID) -> str | None: ...

    @abstractmethod
    async def set_password(self, user_id: UserID, hashed_password: str) -> None: ...

    @abstractmethod
    async def store_refresh_token(self, token: RefreshToken) -> None: ...

    @abstractmethod
    async def get_refresh_token(self, token_str: str) -> RefreshToken | None: ...

    @abstractmethod
    async def revoke_refresh_token(self, token_str: str) -> bool:
        """Atomically flip the token row from not-revoked to revoked. Returns True
        if the caller won the transition (token was present and was not yet revoked),
        False if the token was missing or already revoked. Callers treat False as
        the reuse/concurrent-use signal = the token family should be revoked.
        """
        ...

    @abstractmethod
    async def revoke_refresh_token_family(self, family_id: str) -> None: ...

    @abstractmethod
    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def set_user_verified(self, user_id: UserID) -> None: ...

    async def prune_expired_refresh_tokens(self, before: "datetime | None" = None) -> int:
        """Delete refresh tokens that expired before ``before`` (default: now).

        Rotation writes a row per refresh, so the table only grows; call this
        periodically from your own scheduler. Only expired rows go: a revoked but
        unexpired row is what reuse detection matches a replayed token against,
        and deleting it early would turn a stolen-token replay into an ordinary
        rejection, leaving the family alive.

        Returns the number of rows removed. The default removes nothing, so
        custom adapters keep working; the bundled adapters override it.
        """
        return 0

    async def get_user_roles(self, user_id: UserID) -> list[str]:
        """Get user's roles. Returns [] by default. Override or use RoleAdapterMixin."""
        return []

    # ── User id typing ───────────────────────────────────────────────

    def user_id_annotation(self) -> Any:
        """The primary key type declared on the configured user schema.

        A schema that does not parameterise ``UserSchema`` reports the type
        variable itself rather than its default, so resolve that back to the
        default here.
        """
        schema = getattr(self, "_user_schema", None)
        if schema is None:
            return UUID
        field = schema.model_fields.get("id")
        annotation = None if field is None else field.annotation
        if annotation is None:
            return UUID
        if isinstance(annotation, TypeVar):
            default = getattr(annotation, "__default__", None)
            return default if isinstance(default, type) else UUID
        return annotation

    def parse_user_id(self, raw: str) -> UserID:
        """Convert a token subject back into this adapter's user id type.

        Tokens carry the subject as text, so it has to be converted back before
        a lookup. The user schema you pass to the adapter is what decides the
        target type, which is why ``UserSchema[int]`` needs no extra wiring.
        Raises ``pydantic.ValidationError`` when the subject cannot be converted;
        callers turn that into a 401.
        """
        return cast(UserID, _id_type_adapter(self.user_id_annotation()).validate_python(raw))

    def model_user_id_type(self) -> Any | None:
        """The primary key type of the user model, or None when unknown.

        Adapters override this so a schema/database mismatch can be caught at
        construction. Returning None disables the check for storage whose key
        type cannot be read reliably.
        """
        return None

    def related_user_id_types(self) -> dict[str, Any]:
        """The ``user_id`` type each related model stores, keyed by model name.

        The bundled mixins default ``user_id`` to UUID, so an integer-keyed app
        that forgets to override it on one related model would only fail on
        insert, and not at all on SQLite. Adapters override this so the
        construction-time check covers those models too; models whose key type
        cannot be read reliably are left out.
        """
        return {}

    def validate_user_id_type(self) -> None:
        """Raise when the schema, user model, and related models disagree on key type.

        Without this the mismatch is silent and miserable to debug: the subject
        parses, every lookup misses, and each request fails as a 401. Adapters
        call this once their models and schema are set.
        """
        schema_type = _without_none(self.user_id_annotation())
        model_type = _without_none(self.model_user_id_type())
        if model_type is not None and not _key_types_match(schema_type, model_type):
            raise ValueError(
                f"User id type mismatch: the user schema "
                f"({getattr(self, '_user_schema', type(None)).__name__}) declares "
                f"id: {_type_name(schema_type)}, but the user model "
                f"({getattr(self, '_user_model', type(None)).__name__}) stores "
                f"{_type_name(model_type)}. Parameterise the schema to match, for "
                f"example class MyUser(UserSchema[{_type_name(model_type)}])."
            )

        for model_name, related_annotation in self.related_user_id_types().items():
            related_type = _without_none(related_annotation)
            if not _key_types_match(schema_type, related_type):
                raise ValueError(
                    f"User id type mismatch: {model_name}.user_id stores "
                    f"{_type_name(related_type)}, but user ids are "
                    f"{_type_name(schema_type)}. Override user_id on {model_name} "
                    f"to use the same type as the user primary key."
                )

    def supports_feature(self, feature: AdapterFeature) -> bool:
        """Whether this adapter can actually serve ``feature``.

        FullAuth uses this to decide which routers
        to register and to warn at startup about features configured against an
        adapter that can't serve them.

        The default answers based on which mixins the adapter inherits, which is
        correct for custom adapters that only inherit the mixins they implement.
        The built-in SQL adapters statically inherit every mixin, so they
        override this to report capability from the model classes actually
        passed to the constructor.
        """
        mixin = _FEATURE_MIXINS.get(feature)
        return mixin is not None and isinstance(self, mixin)

    @asynccontextmanager
    async def transaction(
        self,
    ) -> "AsyncIterator[AbstractUserAdapter[UserSchemaType, CreateUserSchemaType]]":
        """Group several adapter calls so they commit or roll back together.

        The default yields ``self`` with no atomicity guarantee, so custom
        adapters keep working unchanged. The built-in SQL adapters override this
        to run the block in a single database transaction - which the
        refresh-token rotation relies on so that revoking the old token and
        storing the new one can't be split by a crash (leaving an orphaned
        session). Override this when your storage can do better than best-effort.
        """
        yield self


class RoleAdapterMixin(ABC):
    """Mixin for role management. Inherit alongside AbstractUserAdapter."""

    @abstractmethod
    async def get_user_roles(self, user_id: UserID) -> list[str]: ...

    @abstractmethod
    async def assign_role(self, user_id: UserID, role_name: str) -> None: ...

    @abstractmethod
    async def remove_role(self, user_id: UserID, role_name: str) -> None: ...


class PermissionAdapterMixin(ABC):
    """Mixin for RBAC permissions. Inherit alongside AbstractUserAdapter."""

    @abstractmethod
    async def get_role_permissions(self, role_name: str) -> list[str]: ...

    async def get_permissions_for_roles(self, role_names: list[str]) -> list[str]:
        """Batch fetch permissions for multiple roles. Override for single-query impl."""
        perms: set[str] = set()
        for role in role_names:
            perms.update(await self.get_role_permissions(role))
        return list(perms)

    async def get_user_permissions(self, user_id: UserID) -> list[str]:
        """Resolve permissions through the user's roles in a single batch."""
        roles = await cast("_SupportsUserRoles", self).get_user_roles(user_id)
        if not roles:
            return []
        return await self.get_permissions_for_roles(roles)

    @abstractmethod
    async def assign_permission_to_role(self, role_name: str, permission: str) -> None: ...

    @abstractmethod
    async def remove_permission_from_role(self, role_name: str, permission: str) -> None: ...


class OAuthAdapterMixin(ABC):
    """Mixin for OAuth account management. Inherit alongside AbstractUserAdapter."""

    @abstractmethod
    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccount | None: ...

    @abstractmethod
    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]: ...

    @abstractmethod
    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount: ...

    @abstractmethod
    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None: ...

    @abstractmethod
    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None: ...


class SessionAdapterMixin(ABC):
    """Mixin for user session management. Inherit alongside AbstractUserAdapter.

    A session is one refresh-token family. The built-in SQL adapters implement
    this automatically; custom adapters inherit it to expose the sessions router.
    """

    @abstractmethod
    async def list_user_sessions(self, user_id: UserID) -> list[SessionInfo]:
        """Return the user's active sessions (live refresh-token families),
        most recently used first."""
        ...

    @abstractmethod
    async def revoke_user_session(self, user_id: UserID, family_id: str) -> bool:
        """Revoke one of the user's sessions. Returns True if a session with that
        family_id existed for the user (idempotent), False if it did not = the
        caller is not the owner, so the route answers 404."""
        ...

    @abstractmethod
    async def revoke_user_sessions_except(self, user_id: UserID, keep_family_id: str) -> int:
        """Revoke all of the user's live sessions except ``keep_family_id``.
        Returns the number of refresh tokens revoked."""
        ...


class PasskeyAdapterMixin(ABC):
    """Mixin for passkey/WebAuthn credential management."""

    @abstractmethod
    async def get_passkey_by_credential_id(
        self, credential_id: str
    ) -> PasskeyCredential | None: ...

    @abstractmethod
    async def get_user_passkeys(self, user_id: UserID) -> list[PasskeyCredential]: ...

    @abstractmethod
    async def store_passkey(self, data: PasskeyCredential) -> PasskeyCredential: ...

    @abstractmethod
    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> bool:
        """Conditionally advance sign_count. Returns True if the new value was strictly
        greater than the stored value and the row was updated; False if the condition
        failed (stale read / concurrent write / authenticator doesn't maintain a counter).
        """
        ...

    @abstractmethod
    async def delete_passkey(self, passkey_id: UUID) -> None: ...


# Maps the feature names used by supports_feature() to the mixin that implements
# them. Defined after the mixins so the references resolve.
_FEATURE_MIXINS: dict[str, type] = {
    "role": RoleAdapterMixin,
    "permission": PermissionAdapterMixin,
    "oauth": OAuthAdapterMixin,
    "passkey": PasskeyAdapterMixin,
    "session": SessionAdapterMixin,
}
