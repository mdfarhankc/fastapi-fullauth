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

Currently an alias for `require_role`. Provided for semantic clarity when your access model uses permission strings like `"posts:delete"`.

```python
from fastapi_fullauth.dependencies import require_permission

@app.delete("/posts/{id}")
async def delete_post(id: str, user=Depends(require_permission("posts:delete"))):
    ...
```

## How it works

All dependencies follow the same flow:

1. Extract the JWT from the `Authorization: Bearer <token>` header (or cookie backend)
2. Decode and validate the token (expiry, blacklist, signature)
3. Look up the user by `sub` (user ID) from the token payload
4. Apply additional checks (verified, superuser, roles)

If any step fails, a `401 Unauthorized` or `403 Forbidden` response is returned automatically.

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
