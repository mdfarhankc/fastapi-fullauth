# Composable design — the "opt-in" philosophy

The guiding rule: **users get only what they opt into**. Apps that don't need roles never see a roles column, a user-roles link table, or an admin router. Apps that don't need OAuth don't get an `oauth_accounts` table. This is why the library splits things the way it does.

If you're tempted to "just add X for convenience," first ask "does every app need this?" If the answer is no, make it opt-in.

## Four opt-in surfaces

1. **Models** — tables you get
2. **Routers** — HTTP surface area
3. **Schemas** — fields on `UserSchema` / `CreateUserSchema`
4. **Adapter mixins** — methods the adapter exposes

They're independent knobs. Turn on what you need, ignore the rest.

## Models: lazy imports

`fastapi_fullauth.adapters.sqlmodel.models` is a package, not a module. Importing the package doesn't import any tables — submodule attribute access does.

```python
# This registers ONLY the user + refresh-token tables:
from fastapi_fullauth.adapters.sqlmodel.models.base import UserBase

# This additionally registers Role + UserRoleLink:
from fastapi_fullauth.adapters.sqlmodel.models.role import Role, UserRoleLink  # noqa: F401

# etc. for permission, oauth, passkey
```

The submodules (`role`, `permission`, `oauth`, `passkey`) aren't imported as a side-effect of touching the package. This is done via a lazy `__getattr__` in `models/__init__.py` — grabbing `models.Role` at runtime triggers the import, but the bare `from ...models.base import UserBase` doesn't.

**Why it matters:** a table that's imported registers itself with `MetaData`. `alembic revision --autogenerate` picks it up. `create_all` creates it. Apps that don't need that table get a clean schema.

## Routers: `exclude_routers` and adapter-driven auto-skip

```python
fullauth.init_app(app, exclude_routers=["admin", "oauth"])
```

Valid names: `"auth"`, `"profile"`, `"verify"`, `"admin"`, `"oauth"`, `"passkey"`. Unknown names raise `ValueError` at init.

On top of that, routers auto-skip when your adapter doesn't implement the matching mixin:

| Router    | Requires mixin            |
|-----------|---------------------------|
| `admin`   | `RoleAdapterMixin`        |
| `oauth`   | `OAuthAdapterMixin`       |
| `passkey` | `PasskeyAdapterMixin`     |

A custom adapter that implements only `AbstractUserAdapter` — no mixins — gets `auth` + `profile` + `verify` routers and nothing else. No 501s, no half-wired features.

## Schemas: opt in per field

`UserSchema` is deliberately minimal:

```python
class UserSchema(BaseModel):
    id: UserID
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
```

No `roles`. No `display_name`. Apps that need either extend the schema:

```python
from pydantic import Field
from fastapi_fullauth.types import UserSchema

class MyUser(UserSchema):
    roles: list[str] = Field(default_factory=list)
    display_name: str | None = None
```

Pass `MyUser` to both `SQLModelAdapter(user_schema=MyUser)` and via the generic parameter so typing propagates. `require_role` / `require_permission` read `user.roles` at request time — if you use those dependencies, you need a `roles` field. If not, leave it off.

Same with `CreateUserSchema`: extend to accept fields you want the registration endpoint to take:

```python
from fastapi_fullauth.types import CreateUserSchema

class MyCreateUser(CreateUserSchema):
    display_name: str | None = None
```

The adapter's `create_user` calls `data.model_dump(exclude={"email", "password"})` and passes the remaining fields to your User model constructor — so any extra field that exists on both sides works transparently.

## Adapter mixins

See `adapters.md` for the full picture. Short version: inherit the mixin for each feature you want, skip the ones you don't. Route auto-skip does the rest.

## What `has_usable_password` is for

OAuth-only users are created with a random password they don't know and `has_usable_password=False`. Two consequences:

- `change-password` rejects them (they can't supply the current password they don't have).
- `set-password` accepts them (it's their first time setting one).

`has_usable_password` is on `UserBase` and `UserSchema` by default. This is one opinionated inclusion — splitting it further would complicate every OAuth app. If you really don't want OAuth, setting the field is free and costs nothing.

## Why not a "config flag for everything"?

Two reasons:

1. **Dead surface area is dangerous.** A router that exists but errors out silently is worse than a router that doesn't exist. Removing it from the app entirely is cleaner — dependency injectors, OpenAPI docs, static analysers, frontends all see the real surface.
2. **Opt-in avoids accidental opinions.** Adding `roles` to the default schema forces every app to have a `roles` list. Adding it *only when the user subclasses* means the app author made a deliberate choice.

When modifying the library, follow the same pattern. A feature addition that "just works for everyone" either demonstrates it's truly core (rare) or it should be gated behind a mixin / submodule / config flag.

## Good signals you're following this

- A consumer who does `pip install fastapi-fullauth` and uses only `auth`+`profile` should not have `fullauth_oauth_accounts`, `fullauth_roles`, or `fullauth_passkeys` in their database.
- Running their app should show no `UserWarning` for features they don't use.
- Their OpenAPI schema should not advertise `/oauth/*` or `/passkeys/*`.
- `alembic autogenerate` should not pick up tables from features they don't use.
