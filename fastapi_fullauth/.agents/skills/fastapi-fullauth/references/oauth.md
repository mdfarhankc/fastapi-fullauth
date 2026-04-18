# OAuth2 social login

The library ships two providers (GitHub, Google) and a base class for the rest. The flow is standard authorization-code with a signed state token — no extra configuration for PKCE or nonces.

## Feature matrix

- **Built-in providers:** `GithubProvider`, `GoogleProvider`
- **Adapter mixin:** `OAuthAdapterMixin`
- **Router:** `oauth`
- **Extra:** `fastapi-fullauth[oauth]` (pulls in `httpx`)
- **Tables:** `fullauth_oauth_accounts` — registered only when `models/oauth.py` is imported

## Setup

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.adapters.sqlmodel.models.oauth import OAuthAccountRecord  # noqa: F401
from fastapi_fullauth.oauth import GithubProvider, GoogleProvider

github = GithubProvider(
    client_id=os.environ["GITHUB_CLIENT_ID"],
    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    redirect_uris=["https://app.example.com/auth/oauth/github/callback"],
)

google = GoogleProvider(
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    redirect_uris=["https://app.example.com/auth/oauth/google/callback"],
)

fullauth = FullAuth(
    config=FullAuthConfig(),
    adapter=SQLModelAdapter(session_maker=session_maker, user_model=User),
    providers=[github, google],
)
```

The `redirect_uris` list is a whitelist. `/oauth/{provider}/authorize?redirect_uri=...` rejects anything not in it.

## Routes

- `GET  /api/v1/auth/oauth/providers` — list configured providers
- `GET  /api/v1/auth/oauth/{provider}/authorize?redirect_uri=...` — returns the authorization URL to redirect the browser to
- `POST /api/v1/auth/oauth/{provider}/callback` — body `{code, state}` — exchange code for tokens and log the user in
- `GET  /api/v1/auth/oauth/accounts` — list OAuth accounts linked to current user (auth required)
- `DELETE /api/v1/auth/oauth/accounts/{provider}` — unlink a provider (auth required, only works if the user has another login method)

The SPA flow:

1. User clicks "sign in with GitHub" → SPA calls `/authorize?redirect_uri=https://app.example.com/after-oauth`
2. SPA redirects the browser to the returned `authorization_url`
3. GitHub redirects back to `https://app.example.com/after-oauth?code=...&state=...`
4. SPA pulls `code` and `state` from the URL and POSTs to `/callback`
5. Response is a login response (access + refresh tokens)

## State and redirect_uri

State is a JWT carrying `{"purpose": "oauth_state", "nonce": ..., "redirect_uri": ...}`, signed with `SECRET_KEY`. TTL defaults to 300 s (`OAUTH_STATE_EXPIRE_SECONDS`). The `/callback` route validates the state's purpose and expiry; mismatches return 401.

## Auto-link-by-email and the email_verified gate

`OAUTH_AUTO_LINK_BY_EMAIL=True` (default): if an OAuth sign-in resolves to an email that already exists as a local account, the OAuth identity is attached to that account. Useful for "I signed up with password, now I'm adding GitHub" without a separate link step.

**Security caveat** — as of v0.8.0, auto-link only proceeds when `info.email_verified=True` from the provider. Without this gate, anyone who registers a secondary email on GitHub (which GitHub doesn't verify ownership for) could sign in via GitHub and get attached to the victim's local account.

When the gate fires, the callback returns a 4xx with:

> This email is already registered. Sign in with your existing credentials and link your OAuth account from account settings.

UX path: log in with password → `POST /oauth/{provider}/authorize` to get the auth URL → go through the provider flow → `POST /oauth/{provider}/callback`. The callback finds the existing user via the session's authenticated user and links cleanly.

To disable auto-link entirely: `FULLAUTH_OAUTH_AUTO_LINK_BY_EMAIL=False`. Then every OAuth sign-in either finds an existing linked identity or creates a brand-new user, never cross-links.

## What `oauth_callback` actually does

High-level, in `flows/oauth.py`:

```
code + state
   → verify_oauth_state                    # JWT decode + purpose check
   → provider.exchange_code(code, ...)     # tokens
   → provider.get_user_info(tokens)        # OAuthUserInfo
   → link_or_create_user                   # see below
   → issue_oauth_tokens                    # JWT access + refresh pair
```

`link_or_create_user` in order:

1. Look up existing OAuth account by `(provider, provider_user_id)`. If found → log that user in, update access/refresh tokens.
2. No existing link but `auto_link_by_email=True` and `info.email_verified=True` and the email matches an existing local user → link that user.
3. No existing link, email doesn't match or email_verified is False → create a new user with a random password and `has_usable_password=False`.
4. Insert the OAuth account row. If that fails with `IntegrityError` on the composite unique `(provider, provider_user_id)` (concurrent callback), fetch the existing row and return it — both callers linked the same identity.

`after_oauth_login(user, provider, is_new_user)` fires for every successful login, including returning users.

`after_oauth_register(user, user_info)` fires on first-time OAuth signup — use this to prefill name / avatar URL from `user_info.name` / `user_info.picture`.

## The set-password flow for OAuth-only users

Users created via OAuth have `has_usable_password=False`. They can't log in with password because there isn't one they know.

`POST /api/v1/auth/set-password` (authenticated, body: `{password}`) sets an initial password and flips `has_usable_password=True`. `change-password` is gated the other way — it rejects users who don't have one.

This is why you don't just call `change-password` for OAuth users: they have no "current password" to supply.

## Writing a custom provider

```python
from fastapi_fullauth.oauth.base import OAuthProvider
from fastapi_fullauth.types import OAuthUserInfo

class DiscordProvider(OAuthProvider):
    name = "discord"

    @property
    def default_scopes(self) -> list[str]:
        return ["identify", "email"]

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        return (
            "https://discord.com/oauth2/authorize?"
            f"client_id={self.client_id}&"
            f"redirect_uri={redirect_uri}&"
            "response_type=code&"
            f"scope={'+'.join(self.scopes)}&"
            f"state={state}"
        )

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        # POST to the provider's token endpoint
        ...

    async def get_user_info(self, tokens: dict) -> OAuthUserInfo:
        # GET the profile endpoint, return OAuthUserInfo
        return OAuthUserInfo(
            provider="discord",
            provider_user_id=...,
            email=...,
            email_verified=...,
            name=...,
            picture=...,
            raw={...},   # full payload for hooks / debugging
        )
```

Instantiate with `client_id`, `client_secret`, `redirect_uris` and pass to `FullAuth(providers=[...])`.

## Gotchas

- **GitHub's `email_verified`** — fetch the authenticated user's primary email from `/user/emails` and trust only the one with `primary=true, verified=true`. The provider built-in does this; a custom provider needs to do the same.
- **`redirect_uri` must match exactly** between authorize and callback — the provider enforces it, and the library passes it through to `exchange_code`. Query strings count.
- **State token and access token use the same `SECRET_KEY`.** Don't add custom `aud` logic; the purpose claim plus short TTL is what keeps them distinct.
- **Unlinking the only login** — `DELETE /oauth/accounts/{provider}` refuses to unlink a provider if it's the user's only remaining login method (no password, no other provider). It returns 400 with "Set a password first."
- **Composite unique** on `(provider, provider_user_id)` is enforced at the DB level since v0.8.0. If you upgrade from ≤ 0.7.0, autogenerate the Alembic migration before deploying.
