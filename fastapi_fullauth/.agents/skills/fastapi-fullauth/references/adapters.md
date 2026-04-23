# Adapters

The adapter is the library's persistence seam. `FullAuth` calls it, the adapter talks to whatever store you use. Two built-ins ship — `SQLAlchemyAdapter` and `SQLModelAdapter` — and you can write your own.

## Mixin layout

`AbstractUserAdapter` is the core contract: user CRUD, password, refresh-token, email verification. Four optional mixins layer on top:

| Mixin                     | Feature group                | What it unlocks             |
|---------------------------|------------------------------|-----------------------------|
| `RoleAdapterMixin`        | RBAC roles                   | `require_role`, admin router routes that touch roles |
| `PermissionAdapterMixin`  | RBAC permissions             | `require_permission`, permission mgmt on admin router |
| `OAuthAdapterMixin`       | OAuth2 social login          | `oauth` router |
| `PasskeyAdapterMixin`     | WebAuthn passkeys            | `passkey` router |

Built-in adapters inherit all four — an app using just `SQLAlchemyAdapter` gets every feature wired in (provided config enables it). Custom adapters implement only what their app actually uses.

Routers auto-skip when the adapter doesn't implement the corresponding mixin, so you can't accidentally expose a route that can't be backed:

```python
# adapter has no OAuthAdapterMixin → /api/v1/auth/oauth/* is not registered
class MyAdapter(AbstractUserAdapter):
    ...
```

`require_permission` without `PermissionAdapterMixin` raises at request time (`AttributeError` on `get_user_permissions`). `PermissionAdapterMixin` itself leans on `RoleAdapterMixin` — permissions are resolved *through* roles, so implement both together.

## Built-in: SQLModelAdapter

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase
from sqlmodel import Field

class User(UserBase, table=True):
    __tablename__ = "users"
    display_name: str | None = Field(default=None)

engine = create_async_engine("postgresql+asyncpg://...")
session_maker = async_sessionmaker(engine, expire_on_commit=False)

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    user_schema=MyUser,              # optional — defaults to UserSchema
    create_user_schema=MyCreateUser, # optional — defaults to CreateUserSchema
)
```

Important: `expire_on_commit=False`. Without it, accessing attributes after commit triggers lazy loads, which is illegal in async context.

## Built-in: SQLAlchemyAdapter

Same shape, different model base:

```python
from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_fullauth.adapters.sqlalchemy.models.base import UserBase

class User(UserBase):
    __tablename__ = "users"
    # add columns via Mapped/mapped_column
```

Both adapters share the same API. Pick whichever ORM you already use — if you have no preference, SQLModel is a bit more ergonomic for small apps.

## Writing a custom adapter

Minimal skeleton:

```python
from fastapi_fullauth.adapters.base import AbstractUserAdapter
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, UserID, UserSchema

class MemoryAdapter(AbstractUserAdapter[UserSchema, CreateUserSchema]):
    def __init__(self) -> None:
        self._users: dict[UserID, dict] = {}
        self._passwords: dict[UserID, str] = {}
        self._tokens: dict[str, RefreshToken] = {}
        self._user_schema = UserSchema
        self._create_user_schema = CreateUserSchema

    async def get_user_by_id(self, user_id): ...
    async def get_user_by_email(self, email): ...
    async def create_user(self, data, hashed_password): ...
    async def update_user(self, user_id, data): ...
    async def delete_user(self, user_id): ...
    async def get_hashed_password(self, user_id): ...
    async def set_password(self, user_id, hashed_password): ...
    async def store_refresh_token(self, token): ...
    async def get_refresh_token(self, token_str): ...
    async def revoke_refresh_token(self, token_str) -> bool: ...
    async def revoke_refresh_token_family(self, family_id): ...
    async def revoke_all_user_refresh_tokens(self, user_id): ...
    async def set_user_verified(self, user_id): ...
```

Add `RoleAdapterMixin`, `PermissionAdapterMixin`, `OAuthAdapterMixin`, `PasskeyAdapterMixin` to the base list as your app needs.

## Contracts custom adapters must honour

### `create_user` translates uniqueness violations

Two concurrent registrations racing on the same email: the DB unique constraint wins, one INSERT fails with an integrity error. `create_user` catches that and raises `UserAlreadyExistsError`. Without this, callers see a 500.

```python
try:
    await session.commit()
except IntegrityError as e:
    await session.rollback()
    raise UserAlreadyExistsError("...") from e
```

### `revoke_refresh_token` is compare-and-swap

Returns `bool`. `True` means the token transitioned from not-revoked to revoked (the caller won). `False` means the token was missing or already revoked — the router treats that as reuse and burns the family.

A blind `UPDATE ... SET revoked = true` that always returns `None` breaks reuse detection under concurrency. Implement as:

```sql
UPDATE refresh_tokens SET revoked = true
WHERE token = :token AND revoked = false
-- return rowcount == 1
```

### `update_passkey_sign_count` is compare-and-swap

Same shape. Returns `True` only when `new_sign_count > stored_sign_count`. `False` means either the authenticator doesn't maintain a counter (synced passkeys stay at 0) or someone else wrote a ≥ value first — the router rejects the latter as a cloned-authenticator signal.

```sql
UPDATE passkeys SET sign_count = :new, last_used_at = now()
WHERE credential_id = :cid AND sign_count < :new
-- return rowcount > 0
```

### `create_oauth_account` is idempotent on composite identity

Composite unique on `(provider, provider_user_id)` means two concurrent OAuth callbacks for the same identity can collide. Return the existing row instead of erroring — they meant the same thing.

```python
try:
    await session.commit()
except IntegrityError:
    await session.rollback()
    existing = await self.get_oauth_account(data.provider, data.provider_user_id)
    if existing is not None:
        return existing
    raise
```

### Email normalisation

The built-in adapters lowercase + strip email on create, update, and lookup (as of v0.9.0). Custom adapters should do the same — `Alice@X.com` and `alice@X.com` must resolve to the same row on every backend, regardless of collation. If you're migrating from 0.8.0 on a case-sensitive collation (MySQL default, SQL Server), lowercase existing rows before deploy: `UPDATE fullauth_users SET email = LOWER(TRIM(email))`.

### `get_user_by_field` default only handles email

The default implementation dispatches `field="email"` to `get_user_by_email` and raises `NotImplementedError` for anything else. If you enable `LOGIN_FIELD="username"` or similar, override `get_user_by_field`.

## Session lifecycle

Adapter methods own their session. Each method does `async with self._session_maker() as session:`, does its work, commits, and returns. Callers don't see sessions — they see schema objects.

Don't expose raw ORM instances from the adapter. Convert to the `UserSchema` type (`self._user_schema.model_validate(...)`) before returning. The rest of the library assumes schemas, not attached ORM rows.

## Schema-level generics

`AbstractUserAdapter` is generic over `UserSchemaType` and `CreateUserSchemaType`. When your app extends them, pass the classes both to the adapter and to the `FullAuth` constructor so typing flows through route signatures:

```python
adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    user_schema=MyUser,
    create_user_schema=MyCreateUser,
)
```

## Performance notes

- `PermissionAdapterMixin.get_permissions_for_roles` is batched — a single JOIN instead of N+1. The default override loops per-role; the built-in adapters override it with one query. Do the same for custom adapters when you can.
- Relationships on SQLAlchemy models use `lazy="selectin"` where async matters. A custom model that defaults to `lazy="select"` on a relationship will throw `MissingGreenlet` the first time user roles are touched in async.
