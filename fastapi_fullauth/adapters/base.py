from abc import ABC, abstractmethod
from typing import Any, Generic

from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    OAuthAccount,
    RefreshToken,
    UserID,
    UserSchema,
    UserSchemaType,
)


class AbstractUserAdapter(ABC, Generic[UserSchemaType, CreateUserSchemaType]):
    """Interface that every database adapter must implement.


    Implement this for your ORM/database to plug into fastapi-fullauth.
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
    async def create_user(self, data: CreateUserSchemaType, hashed_password: str) -> UserSchemaType: ...

    @abstractmethod
    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchemaType: ...

    @abstractmethod
    async def delete_user(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def get_user_roles(self, user_id: UserID) -> list[str]: ...

    @abstractmethod
    async def get_hashed_password(self, user_id: UserID) -> str | None: ...

    @abstractmethod
    async def set_password(self, user_id: UserID, hashed_password: str) -> None: ...

    @abstractmethod
    async def store_refresh_token(self, token: RefreshToken) -> None: ...

    @abstractmethod
    async def get_refresh_token(self, token_str: str) -> RefreshToken | None: ...

    @abstractmethod
    async def revoke_refresh_token(self, token_str: str) -> None: ...

    @abstractmethod
    async def revoke_refresh_token_family(self, family_id: str) -> None: ...

    @abstractmethod
    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def set_user_verified(self, user_id: UserID) -> None: ...

    @abstractmethod
    async def assign_role(self, user_id: UserID, role_name: str) -> None: ...

    @abstractmethod
    async def remove_role(self, user_id: UserID, role_name: str) -> None: ...

    # ── Permissions (optional — override when using RBAC permissions) ──

    async def get_role_permissions(self, role_name: str) -> list[str]:
        return []

    async def get_user_permissions(self, user_id: UserID) -> list[str]:
        """Resolve permissions through the user's roles. Deduplicated."""
        roles = await self.get_user_roles(user_id)
        perms: set[str] = set()
        for role in roles:
            perms.update(await self.get_role_permissions(role))
        return list(perms)

    async def assign_permission_to_role(self, role_name: str, permission: str) -> None:
        raise NotImplementedError("Implement permission methods to use RBAC permissions")

    async def remove_permission_from_role(self, role_name: str, permission: str) -> None:
        raise NotImplementedError("Implement permission methods to use RBAC permissions")

    # ── OAuth (optional — override when using OAuth) ─────────────────

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        raise NotImplementedError("Implement OAuth adapter methods to use OAuth")

    async def get_user_oauth_accounts(self, user_id: UserID) -> list[OAuthAccount]:
        raise NotImplementedError("Implement OAuth adapter methods to use OAuth")

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        raise NotImplementedError("Implement OAuth adapter methods to use OAuth")

    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None:
        raise NotImplementedError("Implement OAuth adapter methods to use OAuth")

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        raise NotImplementedError("Implement OAuth adapter methods to use OAuth")
