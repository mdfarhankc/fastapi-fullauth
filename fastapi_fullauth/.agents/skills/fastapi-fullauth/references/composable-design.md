# Composable design — the "opt-in" philosophy

The guiding rule: **users get only what they opt into**. Apps that don't need roles never see a roles column, a user-roles link table, or an admin router. Apps that don't need OAuth don't get an `oauth_accounts` table. This is why the library splits things the way it does.

If you're tempted to "just add X for convenience," first ask "does every app need this?" If the answer is no, make it opt-in.

## Four opt-in surfaces

1. **Models** — tables you get
2. **Routers** — HTTP surface area
3. **Schemas** — fields on `UserSchema` / `CreateUserSchema`
4. **Adapter mixins** — methods the adapter exposes

They're independent knobs. Turn on what you need, ignore the rest.

## Models: mixins + lazy imports

`fastapi_fullauth.models.{sqlalchemy,sqlmodel}` ships **mixins** — column-only classes with no `Base` parent and no `table=True`. They are inert until you combine them with `table=True` (SQLModel) or your own `DeclarativeBase` (SQLAlchemy). Only the features you subclass register tables with `MetaData`.

```python
# Core only (users + refresh tokens):
from fastapi_fullauth.models.sqlmodel import RefreshTokenMixin, UserMixin

class RefreshToken(RefreshTokenMixin, table=True): pass
class User(UserMixin, table=True): pass


# Add roles — also registers fullauth_roles, fullauth_user_roles:
from fastapi_fullauth.models.sqlmodel import RoleMixin, UserRoleMixin

class Role(RoleMixin, table=True): pass
class UserRole(UserRoleMixin, table=True): pass
```

The mixin sub-packages use lazy `__getattr__` so `from fastapi_fullauth.models.sqlmodel import RoleMixin` doesn't import the OAuth or passkey sub-modules. Only the mixin you name is loaded, so a minimal app's import graph stays minimal.

**Why it matters:** a table you don't subclass isn't on `MetaData`. `alembic revision --autogenerate` doesn't see it. `create_all` doesn't create it. Apps that don't need that table get a clean schema.

## Routers: `include_routers` and adapter-driven auto-skip

```python
fullauth.init_app(app, include_routers=["auth", "profile", "verify"])
```

`include_routers=None` (default) registers every available router. Valid names: `"auth"`, `"profile"`, `"verify"`, `"admin"`, `"oauth"`, `"passkey"`. Unknown names raise `ValueError` at init.

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

## OAuth-only users have a `NULL` `hashed_password`

The OAuth flow inserts the user with `hashed_password=None` — no fake random hash, no separate `has_usable_password` flag. Consequences:

- `/login` rejects them (the password path needs a hash to verify).
- `/change-password` accepts them without `current_password` — the access token is the auth boundary, and there's no current password to defend against. Once they set one, subsequent calls require it like a normal user.

There's no separate `set-password` route; `/change-password` is the single entry point for both first-time set and subsequent changes.

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
