from typing import Any

from uuid_utils import uuid7

from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.types import CreateUserSchema, OAuthAccount, RefreshToken, UserSchema


class InMemoryAdapter(AbstractUserAdapter):
    def __init__(self, user_schema: type[UserSchema] = UserSchema) -> None:
        self._user_schema = user_schema
        self._users: dict[str, dict[str, Any]] = {}
        self._passwords: dict[str, str] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._roles: dict[str, list[str]] = {}
        self._oauth_accounts: dict[tuple[str, str], OAuthAccount] = {}

    async def get_user_by_id(self, user_id: str) -> UserSchema | None:
        data = self._users.get(user_id)
        if data is None:
            return None
        return self._user_schema(**data)

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        return await self.get_user_by_field("email", email)

    async def get_user_by_field(self, field: str, value: str) -> UserSchema | None:
        for data in self._users.values():
            if data.get(field) == value:
                return self._user_schema(**data)
        return None

    async def create_user(self, data: CreateUserSchema, hashed_password: str) -> UserSchema:
        user_id = str(uuid7())
        user_data = {
            "id": user_id,
            "email": data.email,
            "is_active": True,
            "is_verified": False,
            "is_superuser": False,
            "roles": [],
        }
        # include any extra fields from custom CreateUserSchema
        extra = data.model_dump(exclude={"email", "password"})
        user_data.update(extra)

        self._users[user_id] = user_data
        self._passwords[user_id] = hashed_password
        self._roles[user_id] = []
        return self._user_schema(**user_data)

    async def update_user(self, user_id: str, data: dict[str, Any]) -> UserSchema:
        self._users[user_id].update(data)
        return self._user_schema(**self._users[user_id])

    async def delete_user(self, user_id: str) -> None:
        self._users.pop(user_id, None)
        self._passwords.pop(user_id, None)
        self._roles.pop(user_id, None)

    async def get_user_roles(self, user_id: str) -> list[str]:
        return self._roles.get(user_id, [])

    async def get_hashed_password(self, user_id: str) -> str | None:
        return self._passwords.get(user_id)

    async def set_password(self, user_id: str, hashed_password: str) -> None:
        self._passwords[user_id] = hashed_password

    async def store_refresh_token(self, token: RefreshToken) -> None:
        self._refresh_tokens[token.token] = token

    async def get_refresh_token(self, token_str: str) -> RefreshToken | None:
        return self._refresh_tokens.get(token_str)

    async def revoke_refresh_token(self, token_str: str) -> None:
        tok = self._refresh_tokens.get(token_str)
        if tok:
            tok.revoked = True

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        for tok in self._refresh_tokens.values():
            if tok.family_id == family_id:
                tok.revoked = True

    async def revoke_all_user_refresh_tokens(self, user_id: str) -> None:
        for tok in self._refresh_tokens.values():
            if tok.user_id == user_id:
                tok.revoked = True

    async def set_user_verified(self, user_id: str) -> None:
        if user_id in self._users:
            self._users[user_id]["is_verified"] = True

    async def assign_role(self, user_id: str, role_name: str) -> None:
        roles = self._roles.setdefault(user_id, [])
        if role_name not in roles:
            roles.append(role_name)
        if user_id in self._users:
            self._users[user_id]["roles"] = roles

    async def remove_role(self, user_id: str, role_name: str) -> None:
        roles = self._roles.get(user_id, [])
        if role_name in roles:
            roles.remove(role_name)
        if user_id in self._users:
            self._users[user_id]["roles"] = roles

    # ── OAuth ────────────────────────────────────────────────────────

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None:
        return self._oauth_accounts.get((provider, provider_user_id))

    async def get_user_oauth_accounts(self, user_id: str) -> list[OAuthAccount]:
        return [a for a in self._oauth_accounts.values() if a.user_id == user_id]

    async def create_oauth_account(self, data: OAuthAccount) -> OAuthAccount:
        self._oauth_accounts[(data.provider, data.provider_user_id)] = data
        return data

    async def update_oauth_account(
        self, provider: str, provider_user_id: str, data: dict[str, Any]
    ) -> OAuthAccount | None:
        key = (provider, provider_user_id)
        account = self._oauth_accounts.get(key)
        if account is None:
            return None
        updated = account.model_copy(update=data)
        self._oauth_accounts[key] = updated
        return updated

    async def delete_oauth_account(self, provider: str, provider_user_id: str) -> None:
        self._oauth_accounts.pop((provider, provider_user_id), None)
