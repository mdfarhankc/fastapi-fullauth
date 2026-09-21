# OAuth2 social login

The library ships four providers (GitHub, Google, Discord, GitLab) and a base class for the rest. The flow is standard authorization-code with a signed state token.

## Feature matrix

- **Built-in providers:** `GitHubOAuthProvider`, `GoogleOAuthProvider`, `DiscordOAuthProvider`, `GitLabOAuthProvider`
- **Adapter mixin:** `OAuthAdapterMixin`
- **Router:** `oauth`
- **Extra:** `fastapi-fullauth[oauth]` (pulls in `httpx`)
- **Tables:** `fullauth_oauth_accounts`: registered only when you subclass `OAuthAccountMixin` in your `models/`

## Setup

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
from fastapi_fullauth.models.sqlmodel import OAuthAccountMixin
from fastapi_fullauth.oauth import GitHubOAuthProvider, GoogleOAuthProvider


class OAuthAccount(OAuthAccountMixin, table=True):
    pass


github = GitHubOAuthProvider(
    client_id=os.environ["GITHUB_CLIENT_ID"],
    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    redirect_uris=["https://app.example.com/auth/oauth/github/callback"],
)

google = GoogleOAuthProvider(
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    redirect_uris=["https://app.example.com/auth/oauth/google/callback"],
)

fullauth = FullAuth(
    config=FullAuthConfig(),
    adapter=SQLModelAdapter(
        session_maker=session_maker,
        user_model=User,
        refresh_token_model=RefreshToken,
        oauth_account_model=OAuthAccount,
    ),
    providers=[github, google],
)
```

The `redirect_uris` list is a whitelist. `/oauth/{provider}/authorize?redirect_uri=...` rejects anything not in it.

## Routes

- `GET  /api/v1/auth/oauth/providers`: list configured providers
- `GET  /api/v1/auth/oauth/{provider}/authorize?redirect_uri=...`: returns `{authorization_url, binding}`
- `POST /api/v1/auth/oauth/{provider}/callback`: body `{code, state, binding}`, exchange code for tokens and log the user in
- `GET  /api/v1/auth/oauth/accounts`: list OAuth accounts linked to current user (auth required)
- `DELETE /api/v1/auth/oauth/accounts/{provider}`: unlink a provider (auth required, only works if the user has another login method)
- `GET  /api/v1/auth/oauth/{provider}/link/authorize`: authorization URL for linking to the signed-in account (auth required); same `binding` contract as sign-in
- `POST /api/v1/auth/oauth/{provider}/link/callback`: link that provider account to the signed-in account (auth required); body `{code, state, binding}`, returns the account, issues no tokens

The SPA flow:

1. User clicks "sign in with GitHub" → SPA calls `/authorize?redirect_uri=https://app.example.com/after-oauth`
2. SPA stores the returned `binding` in `sessionStorage` (never in a URL) and redirects the browser to `authorization_url`
3. GitHub redirects back to `https://app.example.com/after-oauth?code=...&state=...`
4. SPA POSTs `code`, `state`, and the stored `binding` to `/callback`, then removes the stored `binding`
5. Response is a login response (access + refresh tokens)

## State, binding, and redirect_uri

State is a JWT carrying `{"purpose": "oauth_state", "nonce": ..., "binding": <sha256 of binding>, "redirect_uri": ...}`, signed with `SECRET_KEY`. TTL defaults to 300 s (`OAUTH_STATE_EXPIRE_SECONDS`), and it is single-use when the blacklist is enabled.

The `binding` binds the state to the client that started the flow, as RFC 9700 requires; a signed state alone allows login CSRF (an attacker makes the victim's browser finish the attacker's login). The callback rejects a missing `binding` with 422 and a mismatched one with 400, checked before the state is burned. When calling the flows directly, `generate_oauth_binding()` creates it and `build_authorization_url`, `exchange_oauth_code`, `oauth_callback`, `generate_oauth_state`, and `verify_oauth_state` all take a required keyword-only `binding`.

## PKCE

PKCE (S256) is enabled by default for providers that support it (Google, GitHub, Discord, GitLab) via the `OAUTH_PKCE_ENABLED` setting. The flow stays stateless: the `code_verifier` is derived from the signed state token's nonce keyed by `SECRET_KEY`, so it never travels through the browser. Because the server derives it, it is defense-in-depth for a confidential client that already sends a `client_secret`; the `binding` is what stops login CSRF. A custom provider opts in by setting `supports_pkce = True` and accepting the `code_challenge` (on `get_authorization_url`) and `code_verifier` (on `exchange_code`) keyword arguments; providers that leave `supports_pkce = False` keep the two-argument method signatures.

## Auto-link-by-email and the email_verified gate

`OAUTH_AUTO_LINK_BY_EMAIL=True` (default): if an OAuth sign-in resolves to an email that already exists as a local account, the OAuth identity is attached to that account. Useful for "I signed up with password, now I'm adding GitHub" without a separate link step.

**Security caveat**: as of v0.8.0, auto-link only proceeds when `info.email_verified=True` from the provider. Without this gate, anyone who registers a secondary email on GitHub (which GitHub doesn't verify ownership for) could sign in via GitHub and get attached to the victim's local account.

When the gate fires, the flow raises `OAuthProviderError`. The router collapses it, like every other OAuth failure, into a generic `400 {"detail": "OAuth authentication failed"}`, so the endpoint cannot be used to probe which emails are registered; the specific reason is only in the server log (`fastapi_fullauth.oauth`, "oauth auto-link refused").

The user signs in with their password instead, then links the provider explicitly: `GET /oauth/{provider}/link/authorize` followed by `POST /oauth/{provider}/link/callback`, both authenticated (see below). That path ignores the provider email entirely, so it also covers a provider account under a different address.

To disable auto-link entirely: `FULLAUTH_OAUTH_AUTO_LINK_BY_EMAIL=False`. Then every OAuth sign-in either finds an existing linked identity or creates a brand-new user, never cross-links.

## What `oauth_callback` actually does

High-level, in `flows/oauth.py`:

```
code + state + binding
   → decode state                          # JWT decode + purpose + binding check, then burn
   → provider.exchange_code(code, ...)     # tokens
   → provider.get_user_info(tokens)        # OAuthUserInfo
   → link_or_create_user                   # see below
   → issue_oauth_tokens                    # JWT access + refresh pair
```

`link_or_create_user` in order:

1. Look up existing OAuth account by `(provider, provider_user_id)`. If found → log that user in, update access/refresh tokens.
2. No existing link but `auto_link_by_email=True` and `info.email_verified=True` and the email matches an existing local user → link that user.
3. No existing link, email doesn't match or email_verified is False → create a new user with `hashed_password=NULL`.
4. Insert the OAuth account row. If that fails with `IntegrityError` on the composite unique `(provider, provider_user_id)` (concurrent callback), fetch the existing row and return it; both callers linked the same identity.

`after_oauth_login(user, provider, is_new_user)` fires for every successful login, including returning users.

`after_oauth_register(user, user_info)` fires on first-time OAuth signup; use this to prefill name / avatar URL from `user_info.name` / `user_info.picture`.

## OAuth-only users setting a password

OAuth users have `hashed_password=NULL`. They can't log in with a password because there isn't one to verify against.

`POST /api/v1/auth/change-password` (authenticated, body: `{new_password}`, `current_password` may be omitted) sets the first password. The route accepts the missing `current_password` only when the stored hash is `NULL`; once a password exists, `current_password` is required like any other change.

Setting that first password also needs recent authentication, because there is no current password to check and it creates a new way into the account: the access token's `auth_time` must be within `FULLAUTH_REAUTH_MAX_AGE_SECONDS` (300 by default), otherwise the route answers `403 Re-authentication required`. Refreshing does not reset `auth_time`, so the user has to sign in again. Tell users to set their password soon after signing in, or raise the window.

There's no separate `set-password` route; `/change-password` handles both first-time set and subsequent changes.

## Writing a custom provider

For a provider with the standard OAuth2 authorization-code wire format, subclass `StandardOAuthProvider`: set the endpoints and implement only the userinfo mapping. PKCE, code exchange, and error handling come from the base.

```python
from fastapi_fullauth.oauth import StandardOAuthProvider
from fastapi_fullauth.types import OAuthUserInfo

class MyProvider(StandardOAuthProvider):
    name = "myprovider"
    display_name = "MyProvider"   # used in log/error messages
    authorization_endpoint = "https://auth.example.com/oauth/authorize"
    token_endpoint = "https://auth.example.com/oauth/token"
    userinfo_endpoint = "https://auth.example.com/oauth/userinfo"

    @property
    def default_scopes(self) -> list[str]:
        return ["openid", "email"]

    async def parse_user_info(self, data: dict, headers: dict) -> OAuthUserInfo:
        if not data.get("sub"):
            raise self._invalid_user_info("sub")
        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=str(data["sub"]),
            email=data.get("email"),
            email_verified=bool(data.get("email_verified", False)),
            name=data.get("name"),
            picture=data.get("picture"),
            raw=data,   # full payload for hooks / debugging
        )
```

Wire-format quirks go in the `_authorize_params` / `_token_request_body` hooks or `extra_authorize_params` (see `GitHubOAuthProvider` and `GoogleOAuthProvider` in the source). A provider that deviates from the standard flow entirely subclasses the bare `OAuthProvider` ABC and implements `get_authorization_url`, `exchange_code`, and `get_user_info` itself.

Instantiate with `client_id`, `client_secret`, `redirect_uris` and pass to `FullAuth(providers=[...])`.

## Gotchas

- **GitHub's `email_verified`**: fetch the authenticated user's primary email from `/user/emails` and trust only the one with `primary=true, verified=true`. The provider built-in does this; a custom provider needs to do the same.
- **`redirect_uri` must match exactly** between authorize and callback; the provider enforces it, and the library passes it through to `exchange_code`. Query strings count.
- **State token and access token use the same `SECRET_KEY`.** Don't add custom `aud` logic; the purpose claim plus short TTL is what keeps them distinct.
- **Unlinking the only login**: `DELETE /oauth/accounts/{provider}` refuses with 400 when unlinking would leave the account with no way to sign in. A stored password, any other linked provider, and any registered passkey all count, so a passwordless user who has a passkey can unlink freely. `DELETE /passkeys/{id}` applies the same rule. Unlinking a provider the user does not have is 404.
- **Composite unique** on `(provider, provider_user_id)` is enforced at the DB level since v0.8.0. If you upgrade from ≤ 0.7.0, autogenerate the Alembic migration before deploying.
