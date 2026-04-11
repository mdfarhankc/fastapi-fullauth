# Custom Token Claims

Embed app-specific data into JWT tokens. Custom claims are available in the `extra` field of decoded token payloads.

## Setup

Pass an async callback to `on_create_token_claims`:

```python
from fastapi_fullauth.types import UserSchema

async def add_claims(user: UserSchema) -> dict:
    return {
        "tenant_id": "acme",
        "plan": "pro",
    }

fullauth = FullAuth(
    secret_key="...",
    adapter=adapter,
    on_create_token_claims=add_claims,
)
```

The returned dict is embedded in the `extra` field of every access token.

## Accessing claims

Custom claims are available when decoding tokens:

```python
payload = await fullauth.token_engine.decode_token(token)
tenant_id = payload.extra.get("tenant_id")
plan = payload.extra.get("plan")
```

## Reserved keys

The following keys cannot be used in custom claims (they're used by the JWT structure):

`sub`, `exp`, `iat`, `jti`, `type`, `roles`, `extra`, `family_id`

If your callback returns any of these, a `ValueError` is raised at token creation time.

## When claims are generated

Custom claims are generated on:

- **Login** — embedded in the access token
- **Token refresh** — regenerated from the current user state
- **OAuth callback** — embedded after OAuth user creation/linking

This means claims stay fresh on each refresh. If a user's plan changes, the next token refresh picks it up.
