
from abc import ABC, abstractmethod
from typing import Any

from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserSchema


class AbstractUserAdapter(ABC):
    """Interface that every database adapter must implement.
    

    Implement this for your ORM/database to plug into fastapi-fullauth.
    """

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> UserSchema | None: ...

    @abstractmethod
    async def get_user_by_email(self, email: str) -> UserSchema | None: ...

    @abstractmethod
    async def create_user(self, data: CreateUserSchema,
                          hashed_password: str) -> UserSchema: ...

    @abstractmethod
    async def update_user(self, user_id: str,
                          data: dict[str, Any]) -> UserSchema: ...

    @abstractmethod
    async def delete_user(self, user_id: str) -> None: ...

    @abstractmethod
    async def get_user_roles(self, user_id: str) -> list[str]: ...

    @abstractmethod
    async def get_hashed_password(self, user_id: str) -> str | None: ...

    @abstractmethod
    async def set_password(
        self, user_id: str, hashed_password: str) -> None: ...

    @abstractmethod
    async def store_refresh_token(self, token: RefreshToken) -> None: ...

    @abstractmethod
    async def get_refresh_token(
        self, token_str: str) -> RefreshToken | None: ...

    @abstractmethod
    async def revoke_refresh_token(self, token_str: str) -> None: ...

    @abstractmethod
    async def revoke_refresh_token_family(self, family_id: str) -> None: ...

    @abstractmethod
    async def set_user_verified(self, user_id: str) -> None: ...

    @abstractmethod
    async def assign_role(self, user_id: str, role_name: str) -> None: ...

    @abstractmethod
    async def remove_role(self, user_id: str, role_name: str) -> None: ...
