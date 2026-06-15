# Writing a Custom Adapter

The built-in [SQLModel](sqlmodel.md) and [SQLAlchemy](sqlalchemy.md) adapters cover any SQLAlchemy-supported database. If your data lives somewhere else - MongoDB, Tortoise ORM, DynamoDB, a REST service - you implement the adapter interface yourself. Nothing else in the library changes.

An adapter is just a class that implements `AbstractUserAdapter`. Add an optional mixin for each feature you want (roles, permissions, OAuth, passkeys, sessions); routers for features you don't implement simply never mount.

## A complete worked example

The adapter below is backed by plain Python dicts, so it needs no database driver and runs as-is. Treat it as a template: replace each dict access with your storage layer's calls and keep the method signatures and contracts identical.

It implements the **core interface** plus the **`RoleAdapterMixin`**, so the admin router and `require_role()` work out of the box.

```python
from typing import Any
from uuid import uuid4

from fastapi_fullauth import CreateUserSchema, UserSchema
from fastapi_fullauth.adapters.base import AbstractUserAdapter, RoleAdapterMixin
from fastapi_fullauth.types import RefreshToken, UserID


class _Record:
    """Internal row: the public schema plus the secrets the schema hides."""

    def __init__(self, user: UserSchema, hashed_password: str | None) -> None:
        self.user = user
        self.hashed_password = hashed_password
        self.roles: list[str] = []


class InMemoryAdapter(
    AbstractUserAdapter[UserSchema, CreateUserSchema],
    RoleAdapterMixin,
):
    def __init__(self) -> None:
        self._user_schema = UserSchema
        self._create_user_schema = CreateUserSchema
        self._users: dict[UserID, _Record] = {}
        self._tokens: dict[str, RefreshToken] = {}

    # --- user CRUD -------------------------------------------------------
    async def get_user_by_id(self, user_id: UserID) -> UserSchema | None:
        rec = self._users.get(user_id)
        return rec.user if rec else None

    async def get_user_by_email(self, email: str) -> UserSchema | None:
        for rec in self._users.values():
            if rec.user.email == email:
                return rec.user
        return None

    async def create_user(
        self, data: CreateUserSchema, hashed_password: str | None
    ) -> UserSchema:
        user = UserSchema(id=uuid4(), email=data.email)
        self._users[user.id] = _Record(user, hashed_password)
        return user

    async def update_user(self, user_id: UserID, data: dict[str, Any]) -> UserSchema:
        rec = self._users[user_id]
        rec.user = rec.user.model_copy(update=data)
        return rec.user

    async def delete_user(self, user_id: UserID) -> None:
        self._users.pop(user_id, None)
        for token_str in [t for t, tok in self._tokens.items() if tok.user_id == user_id]:
            del self._tokens[token_str]

    # --- passwords -------------------------------------------------------
    async def get_hashed_password(self, user_id: UserID) -> str | None:
        rec = self._users.get(user_id)
        return rec.hashed_password if rec else None

    async def set_password(self, user_id: UserID, hashed_password: str) -> None:
        self._users[user_id].hashed_password = hashed_password

    # --- refresh tokens --------------------------------------------------
    async def store_refresh_token(self, token: RefreshToken) -> None:
        self._tokens[token.token] = token

    async def get_refresh_token(self, token_str: str) -> RefreshToken | None:
        return self._tokens.get(token_str)

    async def revoke_refresh_token(self, token_str: str) -> bool:
        tok = self._tokens.get(token_str)
        if tok is None or tok.revoked:
            return False  # missing or already revoked -> reuse signal
        tok.revoked = True  # this caller won the transition
        return True

    async def revoke_refresh_token_family(self, family_id: str) -> None:
        for tok in self._tokens.values():
            if tok.family_id == family_id:
                tok.revoked = True

    async def revoke_all_user_refresh_tokens(self, user_id: UserID) -> None:
        for tok in self._tokens.values():
            if tok.user_id == user_id:
                tok.revoked = True

    # --- verification ----------------------------------------------------
    async def set_user_verified(self, user_id: UserID) -> None:
        rec = self._users[user_id]
        rec.user = rec.user.model_copy(update={"is_verified": True})

    # --- roles (RoleAdapterMixin) ---------------------------------------
    async def get_user_roles(self, user_id: UserID) -> list[str]:
        rec = self._users.get(user_id)
        return list(rec.roles) if rec else []

    async def assign_role(self, user_id: UserID, role_name: str) -> None:
        roles = self._users[user_id].roles
        if role_name not in roles:
            roles.append(role_name)

    async def remove_role(self, user_id: UserID, role_name: str) -> None:
        roles = self._users[user_id].roles
        if role_name in roles:
            roles.remove(role_name)
```

## Register it

A custom adapter plugs into `FullAuth` exactly like a built-in one:

```python
from fastapi import FastAPI

from fastapi_fullauth import FullAuth, FullAuthConfig

app = FastAPI()
fullauth = FullAuth(
    adapter=InMemoryAdapter(),
    config=FullAuthConfig(SECRET_KEY="your-secret-key"),
)
fullauth.init_app(app)
```

Because `InMemoryAdapter` inherits `RoleAdapterMixin`, the admin router mounts automatically. Drop the mixin and the admin routes disappear with no other change - the library decides what to mount by checking `isinstance()` on your adapter at startup.

!!! warning "`update_user` writes verbatim"
    `update_user` applies `data` with no field filtering and can set privileged columns (`is_superuser`, `is_verified`, `hashed_password`). The profile route filters request input through `PROTECTED_FIELDS` before calling it - never pass an unfiltered request body straight to `update_user` from your own code.

## Key method contracts

Most methods are plain CRUD. A few carry semantics the security model depends on:

**`revoke_refresh_token(token_str) -> bool`** must be an atomic compare-and-swap: flip the token from `revoked=False` to `revoked=True` and return `True` only if *this* call performed the flip. Return `False` if the token was missing or already revoked. A `False` result is the reuse/replay signal - the library responds by revoking the entire token family. On a real database, implement this as a single conditional `UPDATE ... WHERE revoked = false` and check the affected-row count, not a read-then-write.

**`get_user_roles(user_id) -> list[str]`** is called at token-creation time; the returned names are embedded in the JWT. Keep it cheap.

**`transaction()`** defaults to a best-effort no-op that yields `self`. Refresh-token rotation revokes the old token and stores the new one inside this block, so if your store supports real transactions, override it to make that pair atomic (the SQL adapters do). Otherwise a crash mid-rotation could orphan a session.

See the [`AbstractUserAdapter` source](https://github.com/mdfarhankc/fastapi-fullauth/blob/main/fastapi_fullauth/adapters/base.py) for the full, annotated interface.

## Opting into more features

Inherit additional mixins to light up more routers. Each is independent - take only what you need.

| Mixin | Enables | Methods to implement |
|-------|---------|----------------------|
| `RoleAdapterMixin` | Admin router, `require_role()` | `get_user_roles`, `assign_role`, `remove_role` |
| `PermissionAdapterMixin` | `require_permission()` | `get_role_permissions`, `assign_permission_to_role`, `remove_permission_from_role` |
| `OAuthAdapterMixin` | OAuth router | `get_oauth_account`, `get_user_oauth_accounts`, `create_oauth_account`, `update_oauth_account`, `delete_oauth_account` |
| `PasskeyAdapterMixin` | Passkey router | `get_passkey_by_credential_id`, `get_user_passkeys`, `store_passkey`, `update_passkey_sign_count`, `delete_passkey` |
| `SessionAdapterMixin` | Sessions router (list/revoke active sign-ins) | `list_user_sessions`, `revoke_user_session`, `revoke_user_sessions_except` |

A session is one refresh-token family. To implement `SessionAdapterMixin`, return a `SessionInfo` per live family. The core only hands you a `RefreshToken` (which has no `created_at`/`last_used_at`), so record those timestamps yourself when you store and rotate tokens, then aggregate them into each `SessionInfo`:

```python
from fastapi_fullauth.adapters.base import SessionAdapterMixin
from fastapi_fullauth.types import SessionInfo, UserID


class InMemoryAdapter(..., SessionAdapterMixin):
    async def list_user_sessions(self, user_id: UserID) -> list[SessionInfo]:
        # one SessionInfo per live family, most-recently-used first
        ...

    async def revoke_user_session(self, user_id: UserID, family_id: str) -> bool:
        # revoke the family if it belongs to this user; return False if it does
        # not (the route answers 404 for a non-owner)
        ...

    async def revoke_user_sessions_except(self, user_id: UserID, keep_family_id: str) -> int:
        # revoke every live family except keep_family_id; return the count
        ...
```

For the passkey `update_passkey_sign_count`, apply the same conditional-update discipline as `revoke_refresh_token`: only advance the count if the new value is strictly greater than the stored one. A failed condition is clone detection.

## Logging in with a field other than email

Override `get_user_by_field` to support username (or any other) login. The default only knows `email`:

```python
async def get_user_by_field(self, field: str, value: str) -> UserSchema | None:
    if field == "email":
        return await self.get_user_by_email(value)
    if field == "username":
        for rec in self._users.values():
            if getattr(rec.user, "username", None) == value:
                return rec.user
        return None
    raise NotImplementedError(f"Lookup by {field!r} not implemented")
```

## Custom user schemas

Adapters are generic over your user schema, so a custom adapter pairs naturally with custom fields. See [Custom schemas](index.md#custom-schemas) for extending `UserSchema` / `CreateUserSchema` and the `PROTECTED_FIELDS` rule that keeps fields out of `PATCH /me`.
