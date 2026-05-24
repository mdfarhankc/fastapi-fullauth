# Event Hooks

Hooks let you run custom logic when auth events happen - send emails, log analytics, sync with external systems - without modifying the core auth flows.

## How hooks work

The `EventHooks` system is a simple async event emitter. You register callbacks with `fullauth.hooks.on()`, and the library calls them automatically when events occur.

Key behaviors:

- Hooks fire **after** the side effect commits. When `after_register` fires, the user is already in the database. When `after_logout` fires, the token is already blacklisted. You can't cancel an operation from a hook.
- **Error isolation**: if a hook raises an exception, it's caught and logged to the `fastapi_fullauth.hooks` logger. The route returns its normal response. Other hooks for the same event still run.
- Hooks run in **registration order**, sequentially (not concurrently).

## Registering hooks

```python
fullauth = FullAuth(adapter=adapter, config=FullAuthConfig(SECRET_KEY="..."))

async def on_register(user):
    print(f"New user: {user.email}")

fullauth.hooks.on("after_register", on_register)
```

## Available events

| Event | Callback signature | When it fires |
|-------|-------------------|---------------|
| `after_register` | `async def(user: UserSchema)` | After user account is created |
| `after_login` | `async def(user: UserSchema)` | After successful password login |
| `after_logout` | `async def(user_id: UserID)` | After access token is blacklisted |
| `after_password_change` | `async def(user: UserSchema)` | After password is updated |
| `after_password_reset` | `async def(user: UserSchema)` | After password reset completes |
| `after_email_verify` | `async def(user: UserSchema)` | After email is verified |
| `after_oauth_login` | `async def(user: UserSchema, provider: str, is_new_user: bool)` | After OAuth login succeeds |
| `after_oauth_register` | `async def(user: UserSchema, user_info: OAuthUserInfo)` | After a new user is created via OAuth |
| `send_verification_email` | `async def(email: str, token: str)` | When email verification is requested |
| `send_password_reset_email` | `async def(email: str, token: str)` | When password reset is requested |

## Examples

### Sending emails

The library generates verification and reset tokens but does not send emails itself. Register hooks to deliver them:

```python
async def send_verification_email(email: str, token: str):
    verify_url = f"https://myapp.com/verify?token={token}"
    await my_email_service.send(
        to=email,
        subject="Verify your email",
        body=f"Click here to verify: {verify_url}",
    )

async def send_password_reset_email(email: str, token: str):
    reset_url = f"https://myapp.com/reset-password?token={token}"
    await my_email_service.send(
        to=email,
        subject="Reset your password",
        body=f"Click here to reset: {reset_url}",
    )

fullauth.hooks.on("send_verification_email", send_verification_email)
fullauth.hooks.on("send_password_reset_email", send_password_reset_email)
```

!!! note
    If you don't register a `send_verification_email` hook, the verification token is generated but never delivered. Same for password reset. The endpoint still returns a success response.

### Audit logging

```python
import logging

audit_log = logging.getLogger("audit")

async def log_login(user):
    audit_log.info("Login: email=%s id=%s", user.email, user.id)

async def log_logout(user_id):
    audit_log.info("Logout: user_id=%s", user_id)

fullauth.hooks.on("after_login", log_login)
fullauth.hooks.on("after_logout", log_logout)
```

### Post-registration setup

Create default resources for new users:

```python
async def create_defaults(user):
    await create_workspace(owner_id=user.id, name="My Workspace")
    await create_user_profile(user_id=user.id)

fullauth.hooks.on("after_register", create_defaults)
```

### OAuth login tracking

```python
async def track_oauth(user, provider, is_new_user):
    if is_new_user:
        await analytics.track("signup", {"provider": provider, "email": user.email})
    else:
        await analytics.track("login", {"provider": provider, "email": user.email})

fullauth.hooks.on("after_oauth_login", track_oauth)
```

## Multiple hooks per event

You can register multiple callbacks for the same event. They run in registration order:

```python
fullauth.hooks.on("after_register", send_welcome_email)
fullauth.hooks.on("after_register", create_default_workspace)
fullauth.hooks.on("after_register", track_signup_analytics)
```

## Error handling in hooks

A hook that raises is caught and logged; the next hook still runs and the route returns its normal response. Auth never returns a 500 because of a notification or analytics failure.

If you need to handle errors within a hook (e.g. retry logic, fallback behavior), use try/except inside your callback:

```python
async def send_welcome_email(user):
    try:
        await email_service.send(to=user.email, subject="Welcome!")
    except Exception:
        logging.getLogger("myapp").warning("Welcome email failed for %s", user.email)
```

To see hook errors from the library itself, configure the logger:

```python
import logging
logging.getLogger("fastapi_fullauth.hooks").setLevel(logging.DEBUG)
```

## Type safety

The `hooks.on()` method uses `@overload` with Protocol types so your IDE can autocomplete callback signatures. The available protocol types are:

| Protocol | Used by | Signature |
|----------|---------|-----------|
| `AfterUserHook` | Most user events | `async def(user: UserSchema)` |
| `AfterLogoutHook` | `after_logout` | `async def(user_id: UserID)` |
| `EmailHook` | Email events | `async def(email: str, token: str)` |
| `AfterOAuthLoginHook` | `after_oauth_login` | `async def(user: UserSchema, provider: str, is_new_user: bool)` |
| `AfterOAuthRegisterHook` | `after_oauth_register` | `async def(user: UserSchema, user_info: OAuthUserInfo)` |

You can import these from `fastapi_fullauth.hooks` if you want to type-annotate your callbacks:

```python
from fastapi_fullauth.hooks import AfterUserHook

on_login: AfterUserHook = my_login_handler
```
