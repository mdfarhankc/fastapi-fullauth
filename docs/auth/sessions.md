# Session Management

A **session** is one refresh-token family: every login starts a new family, and refresh rotation keeps that family alive. The sessions router surfaces those families so a user can see where they're signed in and sign out a specific device, without affecting the others.

## What you get

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/auth/sessions` | List the user's active sessions. The device making the request is flagged `current`. |
| `DELETE` | `/auth/sessions/{family_id}` | Revoke one session. `404` if it isn't the caller's. |
| `POST` | `/auth/sessions/revoke-others` | Sign out everywhere except the current session. |

Each session in the list carries:

```json
{
  "family_id": "9f3c…",
  "ip_address": "203.0.113.7",
  "user_agent": "Mozilla/5.0 …",
  "created_at": "2026-06-11T09:00:00Z",
  "last_used_at": "2026-06-11T11:42:00Z",
  "expires_at": "2026-07-11T09:00:00Z",
  "current": true
}
```

`created_at` is when the session began (the first login), `last_used_at` is the most recent refresh, and `current` marks the session whose access token made the request.

## Enabling it

The router is opt-in like the others, and it mounts automatically for the bundled SQLAlchemy and SQLModel adapters — no extra wiring. It registers under your auth prefix (default `/api/v1/auth`).

```python
fullauth.init_app(app)  # sessions router included by default

# or opt in explicitly alongside the routers you want
fullauth.init_app(app, include_routers=["auth", "profile", "sessions"])
```

To leave it off, omit `"sessions"` from `include_routers`.

## How "current session" works

The access token carries a `family_id` claim identifying its session. When listing, the server compares each session's family against the caller's token and sets `current` on the match. `revoke-others` uses the same claim to decide which session to keep.

Access tokens issued before upgrading don't carry the claim; their `current` flag resolves on the next login or refresh.

## Using a custom adapter

The built-in adapters implement session listing out of the box. A custom adapter opts in by inheriting `SessionAdapterMixin` and implementing three methods:

```python
from fastapi_fullauth.adapters import AbstractUserAdapter, SessionAdapterMixin
from fastapi_fullauth.types import SessionInfo

class MyAdapter(AbstractUserAdapter, SessionAdapterMixin):
    async def list_user_sessions(self, user_id) -> list[SessionInfo]: ...
    async def revoke_user_session(self, user_id, family_id) -> bool: ...
    async def revoke_user_sessions_except(self, user_id, keep_family_id) -> int: ...
```

If the adapter doesn't implement the mixin, the sessions router is skipped — the same way `admin` is skipped without role support.

## Migration

Recording device and IP adds two nullable columns to the refresh-token table: `user_agent` and `ip_address`. Both are nullable, so existing rows stay `NULL` and the change is additive. See [Database Migrations](../migrations.md) for the workflow.
