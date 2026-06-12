# Frontend Integration

This guide walks through implementing authentication flows in your frontend application. The steps are framework-agnostic and apply to React, Next.js, Vue, Flutter, mobile apps, or any HTTP client.

## Token management

### Storing tokens

After login, the server returns an access token and a refresh token. How you store them depends on your setup:

**Bearer token (default)**: the tokens are returned in the JSON response body. Your app stores them and attaches the access token to every request as an `Authorization: Bearer <token>` header. Common storage options:

- **In-memory** (a variable or state) - safest against XSS, but lost on page refresh. Good for SPAs that don't need persistence across tabs.
- **sessionStorage** - persists within the tab, cleared when the tab closes. Accessible to JavaScript on the same origin.
- **localStorage** - persists across tabs and browser restarts. Accessible to JavaScript on the same origin. Convenient but more exposed to XSS.

**Cookie backend**: if you configure `CookieBackend`, the server sets HttpOnly cookies automatically - one for the access token and a separate one for the refresh token. Your app doesn't store or attach anything; the browser carries both. In this mode the `refresh_token` field in the login/refresh JSON is `null` (the token lives only in the HttpOnly cookie and never reaches JavaScript), and `/refresh` and `/logout` read the refresh token from the cookie, so you call them with no body. This is the simplest and most XSS-resistant option, but requires CSRF protection (see below). To limit how widely the refresh cookie travels, pass `CookieBackend(config, refresh_path="/api/v1/auth")` so the browser only sends it to the auth routes.

### Refreshing tokens

Access tokens are short-lived (default 30 minutes). When one expires, use the refresh token to get a new pair:

1. Detect a 401 response from any API call
2. Call `POST /api/v1/auth/refresh` with the refresh token in the body (bearer mode) or with no body (cookie mode - the refresh cookie is sent automatically)
3. Store the new access token (and new refresh token, if rotation is enabled); in cookie mode the browser updates both cookies and the body's `refresh_token` is `null`
4. Retry the original request with the new access token

Most HTTP clients support interceptors or middleware that can handle this transparently. The key is to avoid refreshing multiple times concurrently - if several requests fail at once, queue them and refresh only once.

When rotation is enabled (the default), each refresh call invalidates the old refresh token and returns a new one. Always store the latest refresh token. If you use a stale one, the server revokes the entire session.

### Logging out

Call `POST /api/v1/auth/logout` with the access token. Optionally include the refresh token in the body to revoke the entire session:

```json
POST /api/v1/auth/logout
Authorization: Bearer <access_token>

{"refresh_token": "<refresh_token>"}
```

After logout, clear the stored tokens on the client side.

## CSRF protection (cookie auth only)

If you use `CookieBackend` with `CSRFMiddleware`, the server sets a `fullauth_csrf` cookie on GET requests. On state-changing requests (POST, PUT, DELETE, PATCH), your app must:

1. Read the `fullauth_csrf` cookie value
2. Send it as the `X-CSRF-Token` header

This is only needed for cookie-based auth. Bearer token auth is not vulnerable to CSRF because the token must be explicitly attached by your code.

## OAuth2 login flow

OAuth login is a three-step redirect flow between your frontend, your backend, and the OAuth provider (Google, GitHub, etc.).

### Step 1: Start the flow

Your frontend calls your backend to get the provider's authorization URL:

```
GET /api/v1/auth/oauth/google/authorize?redirect_uri=https://myapp.com/auth/callback
```

The `redirect_uri` tells the provider where to send the user after they authenticate. It must match one of the URIs configured on both the provider's dashboard and in your `FullAuthConfig`.

The backend returns a JSON response with the `authorization_url`. Redirect the user to this URL.

### Step 2: User authenticates with the provider

The user is now on Google's (or GitHub's) login page. After they authenticate, the provider redirects them back to your `redirect_uri` with two query parameters:

```
https://myapp.com/auth/callback?code=abc123&state=eyJ...
```

- `code` is a one-time authorization code
- `state` is a CSRF token your backend generated in Step 1

### Step 3: Exchange the code for tokens

Your frontend reads `code` and `state` from the URL and sends them to your backend:

```
POST /api/v1/auth/oauth/google/callback
{"code": "abc123", "state": "eyJ..."}
```

The backend validates the state, exchanges the code with the provider, creates or links the user account, and returns a JWT token pair. From here, the session works like a normal login.

### Handling the redirect page

Your frontend's callback page (e.g. `/auth/callback`) needs to:

1. Extract `code` and `state` from the URL query parameters
2. Send them to the backend callback endpoint
3. Store the returned tokens
4. Redirect the user to the app (e.g. dashboard)

If the callback fails (expired state, invalid code), show an error and let the user retry.

### Listing available providers

Call `GET /api/v1/auth/oauth/providers` to get the list of configured providers. Use this to dynamically render login buttons (e.g. "Sign in with Google", "Sign in with GitHub").

## Passkey (WebAuthn) flow

Passkeys use the browser's WebAuthn API. The flow involves passing binary data between your backend and the browser's `navigator.credentials` API, with base64url encoding in between.

### Registration (adding a passkey to an existing account)

The user must already be logged in. Registration is a two-step challenge-response:

**Step 1: Get registration options**

Call `POST /api/v1/auth/passkeys/register/begin` with the user's access token. The backend returns WebAuthn creation options including a `challenge_key` and a `challenge`.

**Step 2: Prompt the user**

Pass the options to the browser's `navigator.credentials.create()` API. The browser prompts the user for biometrics (fingerprint, Face ID) or a PIN. A few fields need to be converted from base64url strings to `ArrayBuffer` before passing to the browser API:

- `options.challenge` - the server's challenge
- `options.user.id` - the user identifier

**Step 3: Send the result back**

The browser returns a credential object. Convert its binary fields (`rawId`, `attestationObject`, `clientDataJSON`, transports) to base64url strings and send them to `POST /api/v1/auth/passkeys/register/complete` along with the `challenge_key` and a `device_name`.

The backend verifies the attestation and stores the credential.

### Authentication (logging in with a passkey)

Authentication is passwordless and does not require an existing session:

**Step 1: Get authentication options**

Call `POST /api/v1/auth/passkeys/authenticate/begin`. You can optionally pass an `email` to narrow the allowed credentials, or omit it for discoverable credentials (the browser shows all available passkeys).

**Step 2: Prompt the user**

Pass the options to `navigator.credentials.get()`. Convert `challenge` and each `allowCredentials[].id` from base64url to `ArrayBuffer` first. The browser prompts for biometrics.

**Step 3: Send the result back**

Convert the credential's binary fields (`authenticatorData`, `clientDataJSON`, `signature`, `userHandle`) to base64url strings and send them to `POST /api/v1/auth/passkeys/authenticate/complete` with the `challenge_key`.

The backend verifies the assertion and returns a JWT token pair, just like a normal login.

### Base64url encoding

WebAuthn uses `ArrayBuffer` for binary data, but JSON can't carry binary. The convention is base64url encoding (base64 with `-` instead of `+`, `_` instead of `/`, and no padding `=`).

Your frontend needs two helper functions:

- **base64url to ArrayBuffer**: decode the string from the server before passing to the browser API
- **ArrayBuffer to base64url**: encode the browser's response before sending to the server

Most languages and frameworks have libraries for this. Search for "base64url" or "WebAuthn helpers" in your ecosystem.

### Conditional UI (autofill)

Modern browsers support conditional UI, where passkeys appear in the autofill dropdown alongside passwords. To enable this:

1. Call `POST /api/v1/auth/passkeys/authenticate/begin` without an email (enables discoverable credentials)
2. Pass `mediation: "conditional"` to `navigator.credentials.get()`
3. Add `autocomplete="webauthn"` to your username input field

The browser shows available passkeys in the autofill menu. The user selects one and authenticates without clicking a separate button.

### Managing passkeys

- **List passkeys**: `GET /api/v1/auth/passkeys` returns the user's registered passkeys with device name, transport type, and last-used timestamp. Show this in a settings page so users can see and manage their passkeys.
- **Delete a passkey**: `DELETE /api/v1/auth/passkeys/{id}` removes a passkey. Confirm with the user before deleting.

## Email verification flow

1. After registration, call `POST /api/v1/auth/verify-email/request` with the user's access token. The backend fires the `send_verification_email` hook with a token.
2. Your email contains a link to your frontend (e.g. `https://myapp.com/verify?token=eyJ...`).
3. Your frontend's verify page extracts the token from the URL and calls `POST /api/v1/auth/verify-email/confirm` with `{"token": "eyJ..."}`.
4. On success, the user's `is_verified` flag is set to `true`.

## Password reset flow

1. User clicks "Forgot password" and enters their email. Your frontend calls `POST /api/v1/auth/password-reset/request` with `{"email": "user@example.com"}`.
2. The backend always returns 202 (regardless of whether the email exists) and fires the `send_password_reset_email` hook.
3. Your email contains a link (e.g. `https://myapp.com/reset-password?token=eyJ...`).
4. Your frontend's reset page extracts the token, shows a new password form, and calls `POST /api/v1/auth/password-reset/confirm` with `{"token": "eyJ...", "new_password": "..."}`.
5. On success, all sessions are revoked. The user must log in again with their new password.
