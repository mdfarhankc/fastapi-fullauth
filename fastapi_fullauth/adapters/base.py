from abc import ABC, abstractmethod
from typing import Any, Generic

from fastapi_fullauth.types import (
    CreateUserSchemaType,
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
    UserID,
    UserSchemaType,
)


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
            f"Lookup by '{field}' not implemented — override get_user_by_field()"
        )

    @abstractmethod
    async def create_user(
        self, data: CreateUserSchemaType, hashed_password: str
    ) -> UserSchemaType: ...

    @abstractmethod
    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType: ...

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
        the reuse/concurrent-use signal — the token family should be revoked.
        """
        ...

    @abstractmethod
    async def revoke_refresh_token_family(self, family_id: str) -> None: ...

    @abstractmethod
    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def set_user_verified(self, user_id: UserID) -> None: ...

    async def get_user_roles(self, user_id: UserID) -> list[str]:
        """Get user's roles. Returns [] by default. Override or use RoleAdapterMixin."""
        return []


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
        roles = await self.get_user_roles(user_id)  # type: ignore[attr-defined]
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
    async def delete_passkey(self, passkey_id: UserID) -> None: ...
