# Event hooks

Hooks fire *after* a successful operation. They're how you plug in side-effects — send a welcome email after registration, kick off onboarding after first OAuth login, audit log on password change.

## Registering

```python
from fastapi_fullauth import FullAuth

async def on_register(user):
    await email_service.send_welcome(user.email, user.id)

async def on_login(user):
    await analytics.track("login", user_id=str(user.id))

fullauth = FullAuth(config=..., adapter=...)
fullauth.hooks.on("after_register", on_register)
fullauth.hooks.on("after_login", on_login)
```

You can register multiple handlers per event. They run in insertion order, sequentially awaited.

## Available events and their signatures

| Event                   | Signature                                            | When it fires |
|-------------------------|------------------------------------------------------|---------------|
| `after_register`        | `(user)`                                             | Local `/register` succeeds; also fired for OAuth first-signup |
| `after_login`           | `(user)`                                             | Any successful login — password, OAuth, passkey |
| `after_logout`          | `(user_id)`                                          | `/logout` succeeds |
| `after_oauth_login`     | `(user, provider, is_new_user)`                      | OAuth callback completes; `is_new_user` distinguishes sign-in vs first-signup |
| `after_oauth_register`  | `(user, user_info)`                                  | OAuth first-signup only — `user_info` is the full `OAuthUserInfo` including `name`, `picture`, `raw` payload |
| `send_email_verification` | `(user, token)`                                    | Verification token issued — **you must implement this** to actually send the email |
| `send_password_reset`   | `(user, token)`                                      | Password-reset token issued — same, implement to send |

The two `send_*` events are expected hook points, not optional extras. The library doesn't ship an email sender — hook one up or password reset / email verify are no-ops on the user side.

## Full typed signatures

From `hooks.py`:

```python
class AfterUserHook(Protocol):
    async def __call__(self, user: UserSchema) -> None: ...

class AfterLogoutHook(Protocol):
    async def __call__(self, user_id: UserID) -> None: ...

class AfterOAuthLoginHook(Protocol):
    async def __call__(self, user: UserSchema, provider: str, is_new_user: bool) -> None: ...

class AfterOAuthRegisterHook(Protocol):
    async def __call__(self, user: UserSchema, user_info: OAuthUserInfo) -> None: ...

class EmailHook(Protocol):
    async def __call__(self, user: UserSchema, token: str) -> None: ...
```

Your callable matches the Protocol structurally — no base class to inherit.

## Contract: hooks run after the operation succeeds

The operation (user created, login authenticated, token rotated) has already committed by the time the hook runs. If your hook raises, the exception propagates out of the route and becomes a 500, but the user's state is already changed.

Implications:

- **Don't rely on hooks for validation.** Validate in the flow or the adapter. A hook raising doesn't roll back the registration.
- **Do your own error handling inside the hook** if the side-effect is optional — emailing a welcome that fails shouldn't 500 the register endpoint.
- **Idempotency helps.** A user who retries a failed registration might see `after_register` fire twice if the first attempt's hook raised after the user was created. Make email sends idempotent or keyed on user id.

## Typical wire-up for email

```python
async def send_verification_email(user, token):
    url = f"https://app.example.com/verify?token={token}"
    await ses_client.send(
        to=user.email,
        subject="Verify your email",
        body=f"Click to verify: {url}",
    )

async def send_password_reset_email(user, token):
    url = f"https://app.example.com/reset?token={token}"
    await ses_client.send(
        to=user.email,
        subject="Reset your password",
        body=f"Click to reset: {url}",
    )

fullauth.hooks.on("send_email_verification", send_verification_email)
fullauth.hooks.on("send_password_reset", send_password_reset_email)
```

Without these hooks, the `/verify/request` and `/password-reset/request` endpoints still succeed (returning 204 to avoid user enumeration), they just never produce an email the user receives.

## after_oauth_register — profile prefill

First-time OAuth sign-ups land with a random password and whatever fields `CreateUserSchema` has. If you want to grab the name or avatar from the provider, do it here:

```python
async def on_oauth_register(user, user_info):
    await adapter.update_user(user.id, {
        "display_name": user_info.name,
        "avatar_url": user_info.picture,
    })

fullauth.hooks.on("after_oauth_register", on_oauth_register)
```

`user_info.raw` is the full provider payload if you need fields not on `OAuthUserInfo`.

## Debugging: nothing is firing

- Verify you registered the hook on the same `FullAuth` instance that's bound to the app.
- Hooks are awaited — a non-async callable silently does nothing useful. Every hook must be `async def` (or return an awaitable).
- Hooks are sequential. A slow hook blocks the response. If you want fire-and-forget, schedule work with `asyncio.create_task(...)` inside the hook body.

## What hooks aren't

- **Not a permission check.** Authorization happens before the operation reaches the flow; hooks only see successful, authorized events.
- **Not a transaction.** The DB commit has happened. Don't try to "cancel" the operation from a hook.
- **Not a webhook emitter.** If you want to publish to an external system, do it from the hook body — the library doesn't proxy events out-of-process.
