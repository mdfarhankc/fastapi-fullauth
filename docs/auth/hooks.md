# Event Hooks

Hooks let you run custom logic when auth events happen - send emails, log analytics, sync with external systems - without modifying the core auth flows.

## Registering hooks

```python
fullauth = FullAuth(secret_key="...", adapter=adapter)

async def on_register(user):
    print(f"New user: {user.email}")

fullauth.hooks.on("after_register", on_register)
```

## Available events

### User lifecycle

| Event | Callback signature | When |
|-------|-------------------|------|
| `after_register` | `async def(user: UserSchema)` | After successful registration |
| `after_login` | `async def(user: UserSchema)` | After successful login |
| `after_logout` | `async def(user_id: str)` | After logout |
| `after_password_change` | `async def(user: UserSchema)` | After password change |
| `after_password_reset` | `async def(user: UserSchema)` | After password reset |
| `after_email_verify` | `async def(user: UserSchema)` | After email verification |

### Email events

| Event | Callback signature | When |
|-------|-------------------|------|
| `send_verification_email` | `async def(email: str, token: str)` | When verification is requested |
| `send_password_reset_email` | `async def(email: str, token: str)` | When password reset is requested |

### OAuth events

| Event | Callback signature | When |
|-------|-------------------|------|
| `after_oauth_login` | `async def(user: UserSchema, provider: str, is_new_user: bool)` | After OAuth callback |

## Example: email verification

```python
async def send_verification_email(email: str, token: str):
    # build your verification URL
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
    If you don't register a `send_verification_email` hook, the verification token is still generated but never delivered. Same for password reset.

## Example: audit logging

```python
import logging

logger = logging.getLogger("auth")

async def log_login(user):
    logger.info(f"Login: {user.email} (id={user.id})")

async def log_failed_logout(user_id):
    logger.info(f"Logout: user_id={user_id}")

fullauth.hooks.on("after_login", log_login)
fullauth.hooks.on("after_logout", log_failed_logout)
```

## Multiple hooks per event

You can register multiple callbacks for the same event. They run in registration order:

```python
fullauth.hooks.on("after_register", send_welcome_email)
fullauth.hooks.on("after_register", create_default_workspace)
fullauth.hooks.on("after_register", track_signup_analytics)
```
