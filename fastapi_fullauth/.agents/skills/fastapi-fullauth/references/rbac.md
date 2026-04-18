# RBAC — roles and permissions

Role-based access control is optional. If you're building something that doesn't need admins and regular users distinguished — a personal finance app, a single-tenant API — you can skip this whole feature set and the library won't force any of it on you.

## Two mixins, layered

- **`RoleAdapterMixin`** — users have roles (`list[str]`). That's enough for "is this user an admin?"
- **`PermissionAdapterMixin`** — roles have permissions (`list[str]`). Finer-grained: "can this user edit posts?"

Permissions are resolved *through* roles, so if you use `PermissionAdapterMixin` you also need `RoleAdapterMixin`. The built-in adapters inherit both.

## Turning it on

```python
# models imports — register the role + permission tables
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink  # noqa: F401
from fastapi_fullauth.adapters.sqlmodel.models.permission import (
    Permission,
    RolePermissionLink,
)  # noqa: F401
```

```python
# extend UserSchema to carry roles
from pydantic import Field
from fastapi_fullauth.types import UserSchema

class MyUser(UserSchema):
    roles: list[str] = Field(default_factory=list)

adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    user_schema=MyUser,
)
```

Without the `roles` field on the schema, `require_role` raises `AttributeError` at request time. That's the "opt-in" tax for RBAC.

## Dependencies

```python
from fastapi_fullauth.dependencies import require_role, require_permission

@app.delete("/posts/{id}", dependencies=[require_role("moderator")])
async def delete_post(id: int): ...

@app.post("/billing/charge", dependencies=[require_permission("billing:charge")])
async def charge(): ...
```

Both factories return a dependency callable. `require_role("x")` passes if the user's `roles` list contains `"x"` or if `is_superuser=True`. `require_permission("y")` passes if any of the user's roles grants `"y"`, or if `is_superuser=True`.

You can combine:

```python
@app.post(
    "/admin/dangerous-thing",
    dependencies=[require_role("admin"), require_permission("ops:shutdown")],
)
```

Both must pass. Superuser short-circuits both.

## The admin router

When `RoleAdapterMixin` is present, `init_app` includes the `admin` router:

- `GET    /api/v1/auth/admin/users` — list all users (paginated)
- `GET    /api/v1/auth/admin/users/{id}` — get one
- `PATCH  /api/v1/auth/admin/users/{id}` — update (activate/deactivate, verify, set superuser, update fields)
- `DELETE /api/v1/auth/admin/users/{id}` — delete
- `POST   /api/v1/auth/admin/users/{id}/roles` — assign role
- `DELETE /api/v1/auth/admin/users/{id}/roles/{role}` — remove role

When `PermissionAdapterMixin` is also present, role<->permission management routes are added:

- `POST   /api/v1/auth/admin/roles/{role}/permissions` — assign permission
- `DELETE /api/v1/auth/admin/roles/{role}/permissions/{permission}` — remove

Every admin route requires `require_role("admin")` or `is_superuser=True`. You can't bypass by role-assigning yourself — writes to role tables go through the mixin methods that also enforce the dependency.

## Creating the first admin

Cold-start problem: the admin router needs an admin to call it. Options:

- Seed via a one-off script that calls `adapter.assign_role(user_id, "admin")` after registering the first account.
- Seed via SQL in your migration.
- Flip `is_superuser=True` on one user manually; superuser bypasses every role check, so that user can then assign roles via the admin API.

## Writing a minimal RBAC adapter

If you're not using SQLAlchemy/SQLModel:

```python
from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    RoleAdapterMixin,
    PermissionAdapterMixin,
)

class MyAdapter(AbstractUserAdapter[MyUser, MyCreateUser], RoleAdapterMixin, PermissionAdapterMixin):
    async def get_user_roles(self, user_id): ...             # list[str]
    async def assign_role(self, user_id, role_name): ...
    async def remove_role(self, user_id, role_name): ...

    async def get_role_permissions(self, role_name): ...     # list[str]
    async def assign_permission_to_role(self, role_name, permission): ...
    async def remove_permission_from_role(self, role_name, permission): ...

    # Optional but recommended — single query instead of N+1 via the default
    async def get_permissions_for_roles(self, role_names):
        ...

    # Composable through the above two — default implementation is usually fine
    # async def get_user_permissions(self, user_id): ...
```

## Claims in JWTs

`roles` land in the JWT access token as the `roles` claim, populated from `adapter.get_user_roles(user.id)` at login and refresh time. `require_role` reads from the decoded token's `roles` list (via the `UserSchema` returned by `get_current_user`). That means role changes don't take effect until the user's access token is refreshed.

Typical pattern: set a short access-token lifetime (15 min) and let token rotation propagate role changes organically. For instant revocation, blacklist the user's refresh token — next refresh fails, user is logged out.

## Common misuses

- **`roles` on the default `UserSchema`** — the project deliberately keeps it off. Don't add it upstream unless you actually intend RBAC everywhere.
- **Putting permissions directly on users** — not supported. The model is user → roles → permissions. If you want per-user overrides, model them as "give each user a unique role."
- **Hierarchical roles** — not in the library. `admin` doesn't inherit `user`'s permissions unless you explicitly assign them. If you want hierarchy, build a `get_permissions_for_roles` override that expands a role map.
- **Scopes ≠ permissions** — OAuth scopes describe what an OAuth token can do at the provider. Permissions here describe what a user can do in your app. Different concepts; don't conflate them.
