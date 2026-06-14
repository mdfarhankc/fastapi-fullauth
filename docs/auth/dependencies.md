# Protected Routes

fastapi-fullauth provides FastAPI dependency functions to protect your routes. Build your own `Annotated` types with `Depends()`.

## Setting up dependencies

Create your typed dependencies once (e.g. in `deps.py`):

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, current_active_verified_user, current_superuser

from app.schemas import UserSchema  # your user schema

CurrentUser = Annotated[UserSchema, Depends(current_user)]
VerifiedUser = Annotated[UserSchema, Depends(current_active_verified_user)]
SuperUser = Annotated[UserSchema, Depends(current_superuser)]
```

Then use them in your routes:

```python
@app.get("/profile")
async def profile(user: CurrentUser):
    return {"email": user.email, "roles": user.roles}
```

## Dependency functions

### current_user

Any authenticated user (active account required). Returns `401` if the token is invalid or the user is inactive.

### current_active_verified_user

Authenticated user with a verified email address. Returns `403 Forbidden` if the user's email is not verified.

### current_superuser

Authenticated user with `is_superuser=True`. Returns `403 Forbidden` if the user is not a superuser.

### current_token_payload

The decoded access-token `TokenPayload` for the request, without a database lookup. It reads the token from the `Authorization` header or a cookie backend and validates it (expiry, blacklist, signature, purpose). Use it when you only need token data - your [custom claims](custom-claims.md) live in `payload.extra`:

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import current_token_payload
from fastapi_fullauth.types import TokenPayload

@app.get("/tenant")
async def tenant(payload: TokenPayload = Depends(current_token_payload)):
    return {"tenant_id": payload.extra.get("tenant_id")}
```

Reach for `current_user` when you need the user record; reach for `current_token_payload` when a DB hit would be wasted.

### require_role

Check that the user has at least one of the specified roles. Superusers bypass all role checks.

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import require_role

@app.get("/editor")
async def editor_panel(user=Depends(require_role("editor"))):
    return {"msg": "welcome, editor"}

# multiple roles: user needs at least one
@app.get("/content")
async def content(user=Depends(require_role("editor", "author"))):
    return {"msg": "welcome"}
```

### require_permission

Check that the user has at least one of the specified permissions. Permissions are resolved through roles; a user with role `"editor"` gets all permissions assigned to that role.

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import require_permission

@app.delete("/posts/{id}")
async def delete_post(id: str, user=Depends(require_permission("posts:delete"))):
    ...

# multiple permissions: user needs at least one
@app.put("/posts/{id}")
async def edit_post(id: str, user=Depends(require_permission("posts:edit", "posts:admin"))):
    ...
```

Superusers bypass all permission checks.

#### Setting up permissions

Permissions are assigned to roles, not directly to users:

```bash
# Assign permissions to a role (superuser only)
curl -X POST http://localhost:8000/api/v1/auth/admin/assign-permission \
  -H "Authorization: Bearer <superuser-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "editor", "permission": "posts:create"}'

curl -X POST http://localhost:8000/api/v1/auth/admin/assign-permission \
  -H "Authorization: Bearer <superuser-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "editor", "permission": "posts:edit"}'

# List permissions for a role
curl http://localhost:8000/api/v1/auth/admin/role-permissions/editor \
  -H "Authorization: Bearer <superuser-token>"
# → ["posts:create", "posts:edit"]
```

Or programmatically:

```python
await adapter.assign_permission_to_role("editor", "posts:create")
await adapter.assign_permission_to_role("editor", "posts:edit")
await adapter.remove_permission_from_role("editor", "posts:create")

# resolve all permissions for a user (through their roles)
perms = await adapter.get_user_permissions(user.id)
# → ["posts:edit"]
```

#### require_role vs require_permission

| | `require_role` | `require_permission` |
|---|---|---|
| Checks | Role names on the user | Permissions resolved through roles |
| Setup | Just assign roles | Assign roles + map permissions to roles |
| Use case | Simple apps ("admin vs user") | Fine-grained access ("can edit posts?") |
| Change access | Modify code | Update DB mappings |

## How it works

All dependencies follow the same flow:

1. Extract the JWT from the `Authorization: Bearer <token>` header (or cookie backend)
2. Decode and validate the token (expiry, blacklist, signature)
3. Look up the user by `sub` (user ID) from the token payload
4. Apply additional checks (verified, superuser, roles)

If any step fails, a `401 Unauthorized` or `403 Forbidden` response is returned automatically.

## Custom user schemas

When using custom schemas with extra fields, annotate with your schema type. The dependency returns whatever your adapter produces at runtime, so the extra fields are always there:

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user

from app.schemas import MyUserSchema

CurrentUser = Annotated[MyUserSchema, Depends(current_user)]

@app.get("/profile")
async def profile(user: CurrentUser):
    return {"name": user.display_name}  # IDE knows this field exists
```

## Writing custom dependencies

You can write your own dependency functions for full control over the auth flow. There are two approaches:

### Using get_fullauth

`get_fullauth` is a FastAPI dependency that returns the `FullAuth` instance from `app.state`. It gives you access to the adapter, token engine, config, and everything else:

```python
from uuid import UUID

from fastapi import Depends
from fastapi_fullauth.dependencies import current_token_payload, get_fullauth
from fastapi_fullauth.types import TokenPayload

async def my_current_user(
    fullauth=Depends(get_fullauth),
    payload: TokenPayload = Depends(current_token_payload),
):
    user = await fullauth.adapter.get_user_by_id(UUID(payload.sub))
    # your custom logic: load relations, check feature flags, etc.
    return user
```

Let `current_token_payload` handle token extraction and validation (header or cookie) so you don't reimplement it. This is useful when your dependency lives in a separate module from where you set up FullAuth.

### Using the FullAuth instance directly

If you already have the `FullAuth` instance in scope, just reference it directly:

```python
auth = FullAuth(adapter=my_adapter, config=config)

async def my_current_user():
    user = await auth.adapter.get_user_by_id(...)
    # your custom logic
    return user
```

Both approaches give you the same access. Through the `FullAuth` instance you can reach:

- `adapter` - all DB operations (users, roles, permissions, refresh tokens)
- `token_engine` - decode, create, and blacklist tokens
- `config` - all settings
- `hooks` - event hooks
- `lockout` - account lockout store
- `auth_rate_limiter` - rate limiter
- `challenge_store` - passkey challenges
- `oauth_providers` - registered OAuth providers

## Role management

Roles are managed through the admin endpoints (superuser only):

```bash
# Assign a role
curl -X POST http://localhost:8000/api/v1/auth/admin/assign-role \
  -H "Authorization: Bearer <superuser-token>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "...", "role": "editor"}'

# Remove a role
curl -X POST http://localhost:8000/api/v1/auth/admin/remove-role \
  -H "Authorization: Bearer <superuser-token>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "...", "role": "editor"}'
```

You can also manage roles programmatically through the adapter:

```python
await adapter.assign_role(user_id, "editor")
await adapter.remove_role(user_id, "editor")
roles = await adapter.get_user_roles(user_id)
```
