# Custom Token Claims

Custom claims let you embed app-specific data into JWT tokens. They're available in the `extra` field of every decoded token payload, giving you access to app context without a database lookup on every request.

## What are custom claims

JWTs carry a standard set of claims: `sub` (user ID), `exp` (expiry), `roles`, etc. Custom claims extend this with your own data - tenant IDs, subscription plans, feature flags, or session metadata.

Custom claims live in the token's `extra` field and travel with every request. Downstream services can read them without hitting the database.

## Setup

Pass an async callback to `on_create_token_claims`:

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.types import UserSchema

async def add_claims(user: UserSchema) -> dict:
    return {
        "tenant_id": "acme",
        "plan": "pro",
    }

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="..."),
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

You can also access them in a custom FastAPI dependency:

```python
from fastapi import Depends
from fastapi_fullauth.dependencies import get_fullauth

async def get_tenant(
    fullauth=Depends(get_fullauth),
    token: str = Depends(_extract_token),
):
    payload = await fullauth.token_engine.decode_token(token)
    tenant_id = payload.extra.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="No tenant")
    return tenant_id
```

## Reserved keys

The following keys cannot be used in custom claims:

`sub`, `exp`, `iat`, `jti`, `type`, `roles`, `extra`, `family_id`

If your callback returns any of these, a `ValueError` is raised at token creation time.

## When claims are generated

Custom claims are generated on:

- **Login** - embedded in the access token
- **Token refresh** - the callback runs again with the current user state
- **OAuth callback** - embedded after OAuth user creation/linking
- **Passkey authentication** - embedded in the issued token

On refresh, the callback runs with the current user, so changes to user state (plan upgrade, role change, new tenant) are picked up on the next refresh cycle. Between refreshes, the access token carries its original claims.

!!! note
    There is a staleness window between when a user's state changes and when their access token reflects it. This window is at most `ACCESS_TOKEN_EXPIRE_MINUTES` (default 30 minutes). If you need immediate propagation, the client must explicitly refresh the token.

## Use cases

**Multi-tenant isolation**: embed `tenant_id` so downstream services and middleware can enforce tenant boundaries without a database lookup on every request.

```python
async def add_claims(user):
    return {"tenant_id": str(user.tenant_id)}
```

**Feature flags**: embed the subscription plan so the frontend can gate features client-side.

```python
async def add_claims(user):
    return {"plan": user.subscription_plan, "features": user.feature_flags}
```

**Session metadata**: embed login method for audit trails.

```python
async def add_claims(user):
    return {"login_method": "password"}  # or "oauth:google", "passkey"
```

## Performance considerations

- The callback runs on every token creation (login, refresh, OAuth, passkey). Keep it fast - avoid slow queries or external API calls.
- Read from the already-loaded `user` object when possible instead of making additional database calls.
- Every extra byte increases the JWT size. This matters for cookie-based transport where browsers limit cookies to around 4KB. Keep claims compact.
