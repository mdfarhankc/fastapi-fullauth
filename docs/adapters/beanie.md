# Beanie (MongoDB) Adapter

For projects on [MongoDB](https://www.mongodb.com/) via [Beanie](https://beanie-odm.dev/), the async ODM built on PyMongo's native async driver.

## Installation

```bash
pip install fastapi-fullauth[beanie]
```

## How it differs from the SQL adapters

MongoDB has no foreign keys, no join tables, and no multi-document transactions on a standalone server. The adapter is shaped around what a single document can guarantee atomically instead of around joins:

- **No `session_maker`.** Beanie binds each document class to its collection during `init_beanie()`. The adapter just uses those collections - there is no session factory.
- **Roles and permissions are embedded.** A user's roles are an embedded `roles` array on the user document; a role's granted permissions are an embedded `permissions` array on the role document. There are **no** join collections, so the adapter takes no `user_role_model` / `role_permission_model`.
- **No replica set required.** Refresh-token reuse detection is a single-document compare-and-swap (`find_one_and_update` flipping not-revoked to revoked), which MongoDB guarantees atomically - the same guarantee the SQL adapters get from a transaction, without a replica set. `transaction()` therefore stays best-effort (see [Atomicity](#atomicity-and-transactions)).
- **`delete_user` cascades in application code**, removing the user's refresh-token, OAuth, and passkey documents explicitly, since MongoDB will not cascade for you.

## Setup

### 1. Define your documents

Each class in `fastapi_fullauth.models.beanie` is a ready-to-use Beanie `Document`. Use it directly, or subclass it to add your own fields. Only use the documents for features you need - a minimal setup needs only `UserDocument` and `RefreshTokenDocument`.

```python
from fastapi_fullauth.models.beanie import (
    OAuthAccountDocument,
    PasskeyDocument,
    PermissionDocument,
    RefreshTokenDocument,
    RoleDocument,
    UserDocument,
)


class User(UserDocument):
    display_name: str = ""


class RefreshToken(RefreshTokenDocument):
    pass


class Role(RoleDocument):
    pass


class Permission(PermissionDocument):
    pass


class OAuthAccount(OAuthAccountDocument):
    pass


class Passkey(PasskeyDocument):
    pass
```

`UserDocument` provides these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUID` (UUID7) | Document `_id`, auto-generated |
| `email` | `str` | Unique index |
| `hashed_password` | `str \| None` | Password hash. `None` for OAuth-only users. |
| `is_active` | `bool` | Account active flag |
| `is_verified` | `bool` | Email verified flag |
| `is_superuser` | `bool` | Superuser flag |
| `roles` | `list[str]` | Embedded role membership |
| `created_at` | `datetime` | UTC creation timestamp |

### 2. Create the adapter

```python
from fastapi_fullauth.adapters import BeanieAdapter

adapter = BeanieAdapter(
    user_model=User,
    refresh_token_model=RefreshToken,
    role_model=Role,
    permission_model=Permission,
    oauth_account_model=OAuthAccount,
    passkey_model=Passkey,
)
```

Required kwargs: `user_model`, `refresh_token_model`. Optional kwargs (pass the ones for features you use): `role_model`, `permission_model`, `oauth_account_model`, `passkey_model`. Calling a feature method without its document raises `RuntimeError` naming the missing argument. There is no `user_role_model` / `role_permission_model` - role membership and permission grants are embedded arrays.

### 3. Initialize Beanie and wire into FullAuth

Initialize Beanie in your app's lifespan, registering every document you use. `init_app()` wraps your lifespan so `fullauth.aclose()` runs on shutdown automatically - you only manage the Mongo client teardown:

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI
from beanie import init_beanie
from pymongo import AsyncMongoClient

from fastapi_fullauth import FullAuth, FullAuthConfig

fullauth = FullAuth(adapter=adapter, config=FullAuthConfig(SECRET_KEY="your-secret-key"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient("mongodb://localhost:27017")
    await init_beanie(
        database=client["myapp"],
        document_models=[User, RefreshToken, Role, Permission, OAuthAccount, Passkey],
    )
    yield
    await client.close()


app = FastAPI(lifespan=lifespan)
fullauth.init_app(app)
```

## Collections created

Collections are created lazily by MongoDB from the documents you register:

| Group | Collection | Document |
|-------|------------|----------|
| Core (always) | `fullauth_users`, `fullauth_refresh_tokens` | `UserDocument`, `RefreshTokenDocument` |
| Roles | `fullauth_users.roles` (embedded array) | `UserDocument` |
| Permissions | `fullauth_roles`, `fullauth_permissions` | `RoleDocument`, `PermissionDocument` |
| OAuth | `fullauth_oauth_accounts` | `OAuthAccountDocument` |
| Passkeys | `fullauth_passkeys` | `PasskeyDocument` |

`init_beanie()` builds the unique indexes the adapter relies on: `email` on users, `token` on refresh tokens, `name` on roles and permissions, `credential_id` on passkeys, and the compound `(provider, provider_user_id)` on OAuth accounts. The role document carries the authoritative role-to-permission grants in its embedded `permissions` array; the permission collection is the catalog of known permission names.

Deleting a user removes its refresh tokens, OAuth accounts, and passkeys (the adapter issues those deletes explicitly, since MongoDB has no `ON DELETE CASCADE`). Role membership is embedded on the user document and goes with it.

## Atomicity and transactions

The refresh-token rotation flow revokes the presented token and stores its replacement. Reuse detection - rejecting a refresh token that was already spent - is the security-critical part, and it is a **single-document** compare-and-swap (`find_one_and_update` matching `{token, revoked: false}`). MongoDB guarantees that atomically on any deployment, so this adapter needs no replica set and no multi-document transaction.

`transaction()` is therefore left best-effort (it yields the adapter without wrapping the block): the revoke-old and store-new steps are not a single atomic unit, so a crash in the microsecond between them orphans at most one refresh token, and the user simply logs in again. Reuse detection itself is never weakened by this.

## Custom schemas

Define your own schemas and pass them to the adapter:

```python
from fastapi_fullauth import UserSchema, CreateUserSchema

class MyUserSchema(UserSchema):
    display_name: str = ""

class MyCreateSchema(CreateUserSchema):
    display_name: str = ""

adapter = BeanieAdapter(
    user_model=User,
    refresh_token_model=RefreshToken,
    user_schema=MyUserSchema,
    create_user_schema=MyCreateSchema,
)
```

If your app uses roles, add `roles` to your custom schema so the login response and `/me` expose them:

```python
from pydantic import Field

class MyUserSchema(UserSchema):
    roles: list[str] = Field(default_factory=list)
```

## Migrations

MongoDB is schemaless, so there are no table migrations to run - collections and fields appear as documents are written. `init_beanie()` creates the indexes the adapter needs at startup. If you add fields to a document later, [Beanie's migration tooling](https://beanie-odm.dev/tutorial/migrations/) can backfill existing documents when you need a data migration.
