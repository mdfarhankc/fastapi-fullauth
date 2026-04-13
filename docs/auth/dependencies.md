# Protected Routes

fastapi-fullauth provides FastAPI dependencies to protect your routes. Use them with `Depends()` or the `Annotated` type aliases.

## Dependency types

### CurrentUser

Any authenticated user (active account required).

```python
from fastapi_fullauth.dependencies import CurrentUser

@app.get("/profile")
async def profile(user: CurrentUser):
    return {"email": user.email, "roles": user.roles}
```

### VerifiedUser

Authenticated user with a verified email address.

```python
from fastapi_fullauth.dependencies import VerifiedUser

@app.get("/dashboard")
async def dashboard(user: VerifiedUser):
    return {"email": user.email}
```

Returns `403 Forbidden` if the user's email is not verified.

### SuperUser

Authenticated user with `is_superuser=True`.

```python
from fastapi_fullauth.dependencies import SuperUser

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, admin: SuperUser):
    ...
```

Returns `403 Forbidden` if the user is not a superuser.

### require_role

Check that the user has at least one of the specified roles. Superusers bypass all role checks.

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import require_role

@app.get("/editor")
async def editor_panel(user=Depends(require_role("editor"))):
    return {"msg": "welcome, editor"}

# multiple roles — user needs at least one
@app.get("/content")
async def content(user=Depends(require_role("editor", "author"))):
    return {"msg": "welcome"}
```

### require_permission

Check that the user has at least one of the specified permissions. Permissions are resolved through roles — a user with role `"editor"` gets all permissions assigned to that role.

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import require_permission

@app.delete("/posts/{id}")
async def delete_post(id: str, user=Depends(require_permission("posts:delete"))):
    ...

# multiple permissions — user needs at least one
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

## Typed dependencies for custom schemas

If you use custom user schemas, the default `CurrentUser` type resolves to the base `UserSchema`. Use the factory functions for full type safety:

```python
from typing import Annotated
from fastapi import Depends
from fastapi_fullauth.dependencies import (
    get_current_user_dependency,
    get_verified_user_dependency,
    get_superuser_dependency,
)

# your custom schema
from myapp.schemas import MyUserSchema

MyCurrentUser = Annotated[MyUserSchema, Depends(get_current_user_dependency(MyUserSchema))]
MyVerifiedUser = Annotated[MyUserSchema, Depends(get_verified_user_dependency(MyUserSchema))]
MySuperUser = Annotated[MyUserSchema, Depends(get_superuser_dependency(MyUserSchema))]

@app.get("/profile")
async def profile(user: MyCurrentUser):
    return {"name": user.display_name}  # IDE knows this field exists
```

## Using with the function form

If you prefer the function form over `Annotated` types:

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import current_user, current_active_verified_user, current_superuser

@app.get("/profile")
async def profile(user=Depends(current_user)):
    return user
```

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
