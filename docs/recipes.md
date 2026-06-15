# Recipes

End-to-end examples that combine several customization seams. Each one is self-contained - copy it and adjust. For the individual building blocks, see [Customization](customization.md).

## Multi-tenant SaaS

Give every user a `tenant_id`, stamp it into the JWT, and read it on each request without a database lookup. This combines a [custom field](adapters/index.md#custom-schemas), [custom claims](auth/custom-claims.md), and a [custom dependency](auth/dependencies.md#current_token_payload).

**1. Add the column to your model**

```python
from sqlmodel import Field, Relationship

from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class User(UserMixin, table=True):
    tenant_id: str = Field(default="", index=True)
    refresh_tokens: list[RefreshToken] = Relationship()
```

**2. Extend the schemas**

The read schema exposes `tenant_id` and protects it from `PATCH /me`; the create schema makes it part of registration. Extra create-schema fields are written straight to your model column.

```python
from typing import ClassVar

from fastapi_fullauth import CreateUserSchema, UserSchema


class TenantUser(UserSchema):
    tenant_id: str = ""
    PROTECTED_FIELDS: ClassVar[set[str]] = UserSchema.PROTECTED_FIELDS | {"tenant_id"}


class TenantCreate(CreateUserSchema):
    tenant_id: str
```

**3. Wire the adapter and stamp the claim**

```python
from typing import Any

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter


adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    user_schema=TenantUser,
    create_user_schema=TenantCreate,
)


async def add_claims(user: TenantUser) -> dict[str, Any]:
    return {"tenant_id": user.tenant_id}


fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="your-secret-key"),
    on_create_token_claims=add_claims,
)
```

`POST /register` now accepts `tenant_id` alongside `email` and `password`, and every issued access token carries the tenant in `extra`.

**4. Read the tenant on each request**

```python
from typing import Annotated

from fastapi import Depends
from fastapi_fullauth.dependencies import current_token_payload
from fastapi_fullauth.types import TokenPayload


async def current_tenant(payload: TokenPayload = Depends(current_token_payload)) -> str:
    return payload.extra["tenant_id"]


CurrentTenant = Annotated[str, Depends(current_tenant)]


@app.get("/dashboard")
async def dashboard(tenant: CurrentTenant):
    return {"tenant": tenant}
```

Because the tenant comes from the signed token, there's no database hit per request. Note the [staleness window](auth/custom-claims.md#when-claims-are-generated): a tenant change is picked up on the next token refresh, not instantly.

## Log in with a username instead of email

Email stays the account identifier (it's what verification and password reset use), but users sign in with a username.

**1. Add a `username` column and create field**

```python
from sqlmodel import Field, Relationship

from fastapi_fullauth import CreateUserSchema
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin


class RefreshToken(RefreshTokenMixin, table=True):
    pass


class User(UserMixin, table=True):
    username: str = Field(unique=True, index=True)
    refresh_tokens: list[RefreshToken] = Relationship()


class UsernameCreate(CreateUserSchema):
    username: str
```

**2. Point login at the username field**

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters import SQLModelAdapter


adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    create_user_schema=UsernameCreate,
)

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="your-secret-key", LOGIN_FIELD="username"),
)
```

`POST /register` takes `email`, `password`, and `username`; `POST /login` now takes `username` and `password`. The built-in adapters resolve any model column, so no adapter code is needed. On a [custom adapter](adapters/custom.md), override `get_user_by_field` to handle the new field.

## More

- **Send verification and reset emails** - register `send_verification_email` / `send_password_reset_email` [hooks](auth/hooks.md#sending-emails).
- **Enforce password strength** - configure a [PasswordValidator](auth/passwords.md#custom-rules).
- **Use a non-SQL database** - implement the [adapter interface](adapters/custom.md).
- **Cookie-based SPA auth** - switch to the cookie backend in [Frontend integration](frontend-integration.md).
