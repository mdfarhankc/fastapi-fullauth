# OAuth2 Social Login

Add Google and GitHub login with a few config lines. Users can link multiple providers alongside email/password login.

## Installation

```bash
pip install fastapi-fullauth[oauth]
```

## Configuration

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.oauth.google import GoogleOAuthProvider
from fastapi_fullauth.oauth.github import GitHubOAuthProvider

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="..."),
    providers=[
        GoogleOAuthProvider(
            client_id="your-google-client-id",
            client_secret="your-google-secret",
            redirect_uris=[
                "http://localhost:3000/auth/callback",
                "https://myapp.com/auth/callback",
            ],
        ),
        GitHubOAuthProvider(
            client_id="your-github-client-id",
            client_secret="your-github-secret",
            redirect_uris=["http://localhost:3000/auth/callback"],
        ),
    ],
)
```

!!! tip
    `redirect_uris` is the list of allowed callback URLs. The client must pass `redirect_uri` as a query parameter in the authorize request — the library validates it against this list.

## Routes

When OAuth providers are configured, these routes are registered automatically:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/oauth/providers` | List configured providers |
| GET | `/auth/oauth/{provider}/authorize` | Get authorization URL |
| POST | `/auth/oauth/{provider}/callback` | Exchange code for tokens |
| GET | `/auth/oauth/accounts` | List linked OAuth accounts |
| DELETE | `/auth/oauth/accounts/{provider}` | Unlink a provider |

## How the flow works

### 1. Get the authorization URL

```
GET /api/v1/auth/oauth/google/authorize?redirect_uri=http://localhost:3000/auth/callback
```

Response:

```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&state=..."
}
```

The `redirect_uri` parameter is optional. If omitted, the first URI in your `redirect_uris` list is used. The value is validated against the allowed list.

### 2. Redirect the user

Your frontend redirects the user to the `authorization_url`. The user authenticates with Google/GitHub.

### 3. Handle the callback

The provider redirects back to your `redirect_uri` with `code` and `state` query parameters. Your frontend sends these to the callback endpoint:

```
POST /api/v1/auth/oauth/google/callback
{
  "code": "4/0AX4XfW...",
  "state": "eyJ..."
}
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": null
}
```

When `INCLUDE_USER_IN_LOGIN=True`, `user` contains the full user object instead of `null`.

From this point on, the session works exactly like email/password login. The user can call `/me`, `/refresh`, `/logout`, etc. with the JWT tokens.

## What happens on callback

1. **State token is verified** (CSRF protection, 5-minute TTL)
2. **Authorization code is exchanged** for provider tokens
3. **User info is fetched** from the provider (email, name, picture)
4. **Account linking logic** runs:
    - If this provider account is already linked → update tokens, return existing user
    - If an account with the same email exists → link the OAuth account to it
    - Otherwise → create a new user with a random password
5. **JWT tokens are issued** (same as regular login)

!!! note
    If the provider reports the email as verified, the user's `is_verified` flag is set to `True` automatically.

## Auto-linking by email

By default, if a user registers with `user@example.com` via email/password, then later logs in with Google using the same email, the accounts are linked automatically. Disable this with:

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        ...,
        OAUTH_AUTO_LINK_BY_EMAIL=False,
    ),
)
```

## Unlinking providers

Users can unlink an OAuth provider:

```
DELETE /api/v1/auth/oauth/accounts/google
```

This is blocked if the OAuth account is the user's only login method (no password set, no other OAuth providers). The user must set a password first.

## Event hooks

```python
async def on_oauth_login(user, provider, is_new_user):
    if is_new_user:
        print(f"New user via {provider}: {user.email}")
    else:
        print(f"Returning user via {provider}: {user.email}")

fullauth.hooks.on("after_oauth_login", on_oauth_login)
```

The `after_register` hook also fires for new OAuth users.

## Provider setup guides

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or select existing)
3. Go to **APIs & Services > Credentials**
4. Create an **OAuth 2.0 Client ID** (Web application)
5. Add your redirect URIs under **Authorized redirect URIs**
6. Copy the Client ID and Client Secret

Default scopes: `openid`, `email`, `profile`

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Set the **Authorization callback URL** to your redirect URI
4. Copy the Client ID and Client Secret

Default scopes: `read:user`, `user:email`
