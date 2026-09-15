# Sessions and token transport

Two related things: the **`sessions` router** (let a user see and revoke where they're signed in) and the **cookie transport** for the refresh token.

## What a "session" is

One **refresh-token family** = one session. Every login mints a new `family_id`; refresh rotation revokes the old token and issues a new one in the same family. So the live token in each family is the current credential for one device, and the family is the session. The `sessions` router reads `fullauth_refresh_tokens` grouped by `family_id` — there is no separate sessions table.

## The router

Opt-in like the others, and it **auto-mounts** for the bundled adapters (and any adapter implementing `SessionAdapterMixin`), exactly the way `admin` mounts when the adapter supports roles. Registered under the auth prefix (default `/api/v1/auth`).

| Method | Route | Behavior |
|--------|-------|----------|
| `GET` | `/sessions` | List the user's active sessions; the caller's own session is flagged `current: true`. |
| `DELETE` | `/sessions/{family_id}` | Revoke one session. `404` if the family isn't the caller's (ownership is scoped by `user_id`). |
| `POST` | `/sessions/revoke-others` | Revoke every session except the caller's current one. Returns a count. |

Each `SessionInfo`: `family_id`, `ip_address`, `user_agent`, `created_at` (first login in the family), `last_used_at` (most recent refresh), `expires_at`, `current`.

## The `current` flag

The access token carries a `family_id` claim (added at token-pair creation). On `GET /sessions` the server matches each family against the caller's token and sets `current`. `revoke-others` uses the same claim to decide which session to keep — and **refuses with 401 if the token has no `family_id`** (it can't tell which to spare), rather than risk signing the caller out of their own session. Access tokens minted before the upgrade lack the claim; their `current` resolves on the next login or refresh.

## Custom adapters

Inherit `SessionAdapterMixin` and implement three methods; without it, the router is silently skipped:

```python
from fastapi_fullauth.adapters import AbstractUserAdapter, SessionAdapterMixin
from fastapi_fullauth.types import SessionInfo

class MyAdapter(AbstractUserAdapter, SessionAdapterMixin):
    async def list_user_sessions(self, user_id) -> list[SessionInfo]: ...
    async def revoke_user_session(self, user_id, family_id) -> bool: ...        # False if not owned
    async def revoke_user_sessions_except(self, user_id, keep_family_id) -> int: ...
```

The flow functions (`fastapi_fullauth.flows.sessions.{list_sessions, revoke_session, revoke_other_sessions}`) wrap these for custom routing.

## Migration

Recording device/origin adds two **nullable** columns to `fullauth_refresh_tokens`: `user_agent` (`String(512)`) and `ip_address` (`String(45)`). Additive; existing rows stay `NULL`. Autogenerate a migration. See `references/migrations.md`.

`ip_address` is resolved from `request` honoring `TRUSTED_PROXY_HEADERS` (same trust boundary as rate limiting) — don't trust `X-Forwarded-For` unless you actually sit behind a proxy that rewrites it.

## Cookie transport for the refresh token

`BearerBackend` (default) returns both tokens in the JSON body. `CookieBackend` carries **both** tokens in separate HttpOnly cookies and keeps the refresh token out of the body:

```python
from fastapi_fullauth.backends import CookieBackend

fullauth = FullAuth(
    config=config,
    adapter=adapter,
    backends=[CookieBackend(config, refresh_path="/api/v1/auth")],
)
```

- Login/OAuth/passkey set `fullauth_access` and `fullauth_refresh` (both HttpOnly). `TokenPair.refresh_token` comes back `None`.
- `/refresh` and `/logout` read the refresh token from the cookie (`handles_refresh_token = True`), so cookie clients call them with **no body**. `/refresh` re-sets both cookies on rotation; `/logout` clears both.
- `refresh_path` (default `"/"`) scopes the refresh cookie — set it to the auth prefix so the browser only sends it to `/refresh` and `/logout`.
- `delete` matches the write's `secure`/`samesite`/`domain`/`path`, or the browser ignores the deletion.

Wiring a `CookieBackend` is exactly when you must add `CSRFMiddleware` — cookies are sent automatically by the browser, so the cookie-carried `/refresh` and `/logout` POSTs need CSRF protection. The library emits a `UserWarning` at init if a `CookieBackend` is present without the middleware. Bearer transport has no such exposure and is unchanged.
