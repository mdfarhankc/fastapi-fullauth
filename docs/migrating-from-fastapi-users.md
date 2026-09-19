# Migrating from fastapi-users

[fastapi-users](https://github.com/fastapi-users/fastapi-users) is in maintenance mode: it still receives security and dependency updates, but no new features, and its maintainers have announced a successor toolkit. If you need refresh tokens, sessions, roles, or passkeys today, this guide moves an existing app across.

The good news first: **password hashes carry over unchanged, and so does your user table.** fastapi-users hashes with [pwdlib](https://github.com/frankie567/pwdlib), which uses `argon2-cffi` and `bcrypt`; fastapi-fullauth verifies both of those formats directly, and rehashes transparently at the next login when the parameters differ from your configured ones. Nobody has to reset a password.

## What you gain, and what you have to build

| | fastapi-users | fastapi-fullauth |
|---|---|---|
| Access tokens | JWT, database, or Redis strategy | JWT |
| Refresh tokens | none | rotation with reuse detection, stored as digests |
| Sessions | none | list devices, revoke one, revoke others |
| Roles and permissions | `is_superuser` only | roles, permissions, `require_role`, `require_permission` |
| Passkeys (WebAuthn) | none | registration and passwordless sign-in |
| Lockout, rate limiting, CSRF, security headers | none | built in |
| User admin CRUD routes | `GET/PATCH/DELETE /{id}` | **not included**; write your own with `require_role`, or call the adapter |
| Link an OAuth account while signed in | `get_oauth_associate_router` | **not yet**; sign-in linking is automatic on a provider-verified email |
| MFA / TOTP | none | none |

Read the [threat model](security/threat-model.md) before you commit: it states plainly what the library defends against and what stays your responsibility.

## Concept mapping

| fastapi-users | fastapi-fullauth |
|---|---|
| `SQLAlchemyUserDatabase`, `BeanieUserDatabase` | an adapter: `SQLModelAdapter`, `SQLAlchemyAdapter`, `TortoiseAdapter`, `BeanieAdapter` |
| `BaseUserManager` subclass | not needed; behaviour comes from config, hooks, and flows |
| `AuthenticationBackend` = transport + strategy | `FullAuth(backends=[...])` for transport; the token engine issues tokens |
| `BearerTransport` / `CookieTransport` | `BearerBackend` / `CookieBackend` |
| `JWTStrategy` | JWT access tokens (`ACCESS_TOKEN_EXPIRE_MINUTES`) plus database-backed refresh tokens |
| `DatabaseStrategy` / `RedisStrategy` | no direct equivalent; revocation is the token blacklist plus refresh-token families |
| `FastAPIUsers[User, uuid.UUID]` | `FullAuth(adapter=..., config=...)` |
| `fastapi_users.current_user(active=True)` | `CurrentUser` (`current_user`) |
| `current_user(active=True, verified=True)` | `VerifiedUser` |
| `current_user(superuser=True)` | `SuperUser` |
| `UserRead` / `UserCreate` / `UserUpdate` | `UserSchema` / `CreateUserSchema`; the `PATCH /me` body is derived from your schema |
| `on_after_register`, `on_after_forgot_password`, ... | `fullauth.hooks.on("after_register")`, `"send_password_reset_email"`, ... |
| `user.id` is `uuid.UUID` | UUID by default; `UserSchema[int]` or `UserSchema[str]` for other keys |

## Route mapping

Your fastapi-users prefixes were whatever you passed to `include_router`; the table uses the prefixes from their documented example. fastapi-fullauth mounts everything under `API_PREFIX + AUTH_ROUTER_PREFIX` (default `/api/v1/auth`).

| fastapi-users | fastapi-fullauth | Notes |
|---|---|---|
| `POST /auth/jwt/login` (form-encoded `username`, `password`) | `POST /login` (JSON `email`, `password`) | response adds `refresh_token`, `expires_in`, `user` |
| `POST /auth/jwt/logout` | `POST /logout` | 204 in both |
| none | `POST /refresh` | new: rotate the token pair |
| `POST /auth/register` | `POST /register` | returns 202 and a generic message by default; set `PREVENT_REGISTRATION_ENUMERATION=False` for 201 plus the user |
| `POST /auth/forgot-password` | `POST /password-reset/request` | |
| `POST /auth/reset-password` | `POST /password-reset/confirm` | body field is `new_password` |
| `POST /auth/request-verify-token` | `POST /verify-email/request` | authenticated; sends to the current user |
| `POST /auth/verify` | `POST /verify-email/confirm` | |
| `GET /users/me` | `GET /me` | |
| `PATCH /users/me` | `PATCH /me` for profile fields, `POST /change-password` for the password | email and other protected fields are not editable here |
| `DELETE /users/me` (not provided) | `DELETE /me` | |
| `GET/PATCH/DELETE /users/{id}` | not included | build your own, see below |
| `GET /auth/{provider}/authorize` | `GET /oauth/{provider}/authorize` | returns `authorization_url` **and a `binding`** your client must store |
| `GET /auth/{provider}/callback` | `POST /oauth/{provider}/callback` | JSON body `{code, state, binding}` |
| `get_oauth_associate_router` | not yet | |
| none | `GET /sessions`, `DELETE /sessions/{family_id}`, `POST /sessions/revoke-others` | new |
| none | `/passkeys/*`, `/admin/assign-role`, `/admin/assign-permission` | new |

## Setup, before and after

=== "fastapi-users"

    ```python
    bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")

    def get_jwt_strategy() -> JWTStrategy:
        return JWTStrategy(secret=SECRET, lifetime_seconds=3600)

    auth_backend = AuthenticationBackend(
        name="jwt", transport=bearer_transport, get_strategy=get_jwt_strategy
    )

    class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
        reset_password_token_secret = SECRET
        verification_token_secret = SECRET

        async def on_after_register(self, user: User, request: Request | None = None):
            print(f"User {user.id} has registered.")

    fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

    app.include_router(fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt")
    app.include_router(fastapi_users.get_register_router(UserRead, UserCreate), prefix="/auth")
    app.include_router(fastapi_users.get_reset_password_router(), prefix="/auth")
    app.include_router(fastapi_users.get_verify_router(UserRead), prefix="/auth")
    app.include_router(fastapi_users.get_users_router(UserRead, UserUpdate), prefix="/users")

    current_active_user = fastapi_users.current_user(active=True)
    ```

=== "fastapi-fullauth"

    ```python
    from fastapi_fullauth import FullAuth, FullAuthConfig
    from fastapi_fullauth.adapters import SQLAlchemyAdapter
    from fastapi_fullauth.dependencies import CurrentUser

    config = FullAuthConfig(SECRET_KEY=SECRET, ACCESS_TOKEN_EXPIRE_MINUTES=60)
    adapter = SQLAlchemyAdapter(
        session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        user_schema=MyUser,
        create_user_schema=MyUserCreate,
    )
    fullauth = FullAuth(adapter=adapter, config=config)

    @fullauth.hooks.on("after_register")
    async def on_register(user):
        print(f"User {user.id} has registered.")

    fullauth.init_app(app)  # mounts every router; use include_routers=[...] to pick

    # CurrentUser is the equivalent of current_user(active=True)
    ```

There is no `UserManager`: registration, verification, and reset live in flows the routers call, and your code hooks into them by event. Email sending moves from `on_after_forgot_password` to the `send_password_reset_email` hook, which the library calls with `(email, token)`.

## Migrating the data

The user columns line up one for one. fastapi-users' table is `user`; the bundled mixins here use `fullauth_users` and add `created_at`.

```sql
INSERT INTO fullauth_users (id, email, hashed_password, is_active, is_verified, is_superuser, created_at)
SELECT id, email, hashed_password, is_active, is_verified, is_superuser, now()
FROM "user";
```

OAuth accounts need renaming. fastapi-users stores `oauth_name`, `account_id`, `account_email`, and an integer `expires_at`:

```sql
INSERT INTO fullauth_oauth_accounts (id, provider, provider_user_id, user_id, provider_email, access_token, refresh_token, expires_at)
SELECT id, oauth_name, account_id, user_id, account_email, access_token, refresh_token,
       to_timestamp(expires_at)
FROM oauth_account;
```

Prefer to keep your existing table names? Define your own models instead of the mixins, or override `__tablename__` on each one and update the foreign keys that point at `fullauth_users.id`. See [Choosing a primary key type](adapters/index.md#choosing-a-primary-key-type) for the same pattern applied to key types.

Refresh tokens, roles, permissions, and passkeys have no counterpart to copy: create those tables empty.

!!! warning
    Issued access tokens do not survive the switch. The claims differ, so everyone is signed out once at cutover and signs in again. Verification and password-reset links already in inboxes stop working too, so cut over at a quiet time, or keep the old app running long enough for those to expire.

## Client changes

- **Login** sends JSON (`{"email": ..., "password": ...}`), not a form body, and returns `access_token`, `refresh_token`, `token_type`, `expires_in`, and `user`.
- **Store the refresh token** and call `POST /refresh` when the access token expires. This is new; a fastapi-users client had nothing to refresh.
- **Register** answers 202 with a generic message by default so the endpoint cannot be used to probe which emails exist. Set `PREVENT_REGISTRATION_ENUMERATION=False` to get the old 201-plus-user behaviour.
- **Password changes** move from `PATCH /users/me` to `POST /change-password`, which takes `current_password` and `new_password`.
- **OAuth** now has a `binding` value: store what `/authorize` returns and send it back with the callback. See [OAuth](oauth.md#security-model).
- **Cookies:** if you used `CookieTransport`, use `CookieBackend` and add `CSRFMiddleware`; see [Frontend integration](frontend-integration.md).

## Rebuilding user administration

There are no `/users/{id}` routes here. Write the few you need against the adapter, protected by a role or the superuser dependency:

```python
from fastapi_fullauth.dependencies import SuperUser

@app.get("/admin/users/{user_id}")
async def read_user(user_id: str, admin: SuperUser):
    user = await fullauth.adapter.get_user_by_id(fullauth.adapter.parse_user_id(user_id))
    if user is None:
        raise HTTPException(404)
    return user

@app.patch("/admin/users/{user_id}")
async def deactivate(user_id: str, admin: SuperUser):
    return await fullauth.adapter.update_user(
        fullauth.adapter.parse_user_id(user_id), {"is_active": False}
    )
```

`update_user` writes what you give it, including privileged columns, so never hand it a request body directly. Role assignment already has routes: `POST /admin/assign-role` and `POST /admin/remove-role`.

## Suggested cutover

1. Stand the new app up against a **copy** of your database and run your test suite against it.
2. Confirm existing users can sign in, which proves the password hashes verify.
3. Port your `UserManager` callbacks to hooks, and register `send_verification_email` and `send_password_reset_email`; without them those tokens are generated and dropped (the library warns at startup).
4. Update clients: JSON login, refresh handling, the password-change route, and the OAuth `binding`.
5. Run `fullauth check` to see the resolved configuration and warnings, and set `REDIS_URL` if you run more than one worker.
6. Cut over during a quiet window and tell users they will be signed out once.

Something in this guide out of date or missing? [Open an issue](https://github.com/mdfarhankc/fastapi-fullauth/issues).
