# Passkeys (WebAuthn)

Passkeys replace passwords with public-key cryptography. The user's device holds a private key; the server stores the public key. Authentication is a challenge-response: the server sends a random nonce, the device signs it, and the server verifies the signature.

Passkeys are phishing-resistant because the browser validates the origin before signing. They work with biometrics (fingerprint, Face ID), PINs, or hardware security keys.

## Prerequisites

```bash
pip install fastapi-fullauth[sqlmodel,passkey]  # or [sqlalchemy,passkey]
```

The `webauthn` package ships in the `passkey` extra, not the core install, so include it above. You also need:

- A `PasskeyMixin` model for storing credentials
- `PasskeyAdapterMixin` on your adapter
- `PASSKEY_ENABLED=True` in config

## Setup

### 1. Define the passkey table

=== "SQLModel"

    ```python
    from fastapi_fullauth.models.sqlmodel import PasskeyMixin

    class Passkey(PasskeyMixin, table=True):
        pass
    ```

=== "SQLAlchemy"

    ```python
    from fastapi_fullauth.models.sqlalchemy import PasskeyMixin

    class Passkey(PasskeyMixin, Base):
        pass
    ```

### 2. Pass the model to the adapter

```python
adapter = SQLModelAdapter(
    session_maker=session_maker,
    user_model=User,
    refresh_token_model=RefreshToken,
    passkey_model=Passkey,           # enables passkey support
)
```

### 3. Configure passkeys

```python
config = FullAuthConfig(
    SECRET_KEY="your-secret-key",
    PASSKEY_ENABLED=True,
    PASSKEY_RP_ID="example.com",
    PASSKEY_RP_NAME="My App",
    PASSKEY_ORIGINS=["https://example.com"],
)
```

!!! warning
    `PASSKEY_RP_ID` must be a bare domain (no scheme, no path). `PASSKEY_ORIGINS` must be full origins including the scheme (e.g. `https://example.com`). The library validates these at startup.

!!! tip
    For local development, use `PASSKEY_RP_ID=localhost` and `PASSKEY_ORIGINS=["http://localhost:8000"]`.

## Routes

All routes are under the auth prefix (default `/api/v1/auth`):

| Method | Path | Auth required | Description |
|--------|------|:---:|-------------|
| POST | `/passkeys/register/begin` | Yes | Start passkey registration |
| POST | `/passkeys/register/complete` | Yes | Finish registration |
| POST | `/passkeys/authenticate/begin` | No | Start authentication |
| POST | `/passkeys/authenticate/complete` | No | Finish authentication, returns JWT tokens |
| GET | `/passkeys` | Yes | List user's passkeys |
| DELETE | `/passkeys/{passkey_id}` | Yes | Delete a passkey |

## Registration flow

Registration adds a new passkey to an existing authenticated user.

**Step 1:** Call the begin endpoint. The server generates WebAuthn creation options and stores a challenge in the challenge store.

```bash
curl -X POST http://localhost:8000/api/v1/auth/passkeys/register/begin \
  -H "Authorization: Bearer <access_token>"
```

Response:

```json
{
  "rp": {"name": "My App", "id": "example.com"},
  "user": {"id": "...", "name": "user@example.com", "displayName": "user@example.com"},
  "challenge": "...",
  "challenge_key": "passkey:reg:abc123...",
  "pubKeyCredParams": [...],
  "excludeCredentials": [...]
}
```

**Step 2:** Pass the options to the browser's WebAuthn API. The browser prompts the user for biometrics or a PIN.

**Step 3:** Send the credential response back to the complete endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/auth/passkeys/register/complete \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_key": "passkey:reg:abc123...",
    "credential": { ... },
    "device_name": "MacBook Pro"
  }'
```

The server verifies the attestation (origin, RP ID, challenge signature) and stores the credential.

## Authentication flow

Authentication is passwordless and does not require an existing session.

**Step 1:** Call the begin endpoint. Optionally pass an email to narrow the allowed credentials:

```bash
# With email hint (shows specific credentials)
curl -X POST http://localhost:8000/api/v1/auth/passkeys/authenticate/begin \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Without email (discoverable credentials / conditional UI)
curl -X POST http://localhost:8000/api/v1/auth/passkeys/authenticate/begin
```

**Step 2:** Pass the options to `navigator.credentials.get()` in the browser.

**Step 3:** Send the credential response to the complete endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/auth/passkeys/authenticate/complete \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_key": "passkey:auth:def456...",
    "credential": { ... }
  }'
```

The server verifies the assertion, checks the sign count (see [Clone detection](#clone-detection)), and returns a JWT token pair.

!!! note
    When an email is provided to `authenticate/begin`, the response always includes an `allowCredentials` list (possibly empty). Callers can't distinguish unknown emails from known ones with no passkeys. This prevents user enumeration.

## Frontend integration

Here's a minimal JavaScript example for registration and authentication:

```javascript
// --- Registration ---
async function registerPasskey(accessToken) {
    // Step 1: get options from server
    const resp = await fetch("/api/v1/auth/passkeys/register/begin", {
        method: "POST",
        headers: { "Authorization": `Bearer ${accessToken}` },
    });
    const options = await resp.json();
    const challengeKey = options.challenge_key;

    // Convert base64url fields to ArrayBuffer for the browser API
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);

    // Step 2: prompt user for biometrics
    const credential = await navigator.credentials.create({ publicKey: options });

    // Step 3: send result back
    await fetch("/api/v1/auth/passkeys/register/complete", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            challenge_key: challengeKey,
            credential: serializeCredential(credential),
            device_name: navigator.userAgent.split(" ").pop(),
        }),
    });
}

// --- Authentication ---
async function authenticatePasskey() {
    const resp = await fetch("/api/v1/auth/passkeys/authenticate/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
    });
    const options = await resp.json();
    const challengeKey = options.challenge_key;

    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id),
        }));
    }

    const credential = await navigator.credentials.get({ publicKey: options });

    const tokenResp = await fetch("/api/v1/auth/passkeys/authenticate/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            challenge_key: challengeKey,
            credential: serializeCredential(credential),
        }),
    });
    return await tokenResp.json(); // { access_token, refresh_token, ... }
}

// --- Helpers ---
function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - base64url.length % 4) % 4);
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/") + padding;
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
}

function bufferToBase64url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function serializeCredential(cred) {
    const result = {
        id: cred.id,
        rawId: bufferToBase64url(cred.rawId),
        type: cred.type,
        response: {},
    };
    if (cred.response.attestationObject) {
        result.response.attestationObject = bufferToBase64url(cred.response.attestationObject);
        result.response.clientDataJSON = bufferToBase64url(cred.response.clientDataJSON);
        result.response.transports = cred.response.getTransports?.() || [];
    } else {
        result.response.authenticatorData = bufferToBase64url(cred.response.authenticatorData);
        result.response.clientDataJSON = bufferToBase64url(cred.response.clientDataJSON);
        result.response.signature = bufferToBase64url(cred.response.signature);
        result.response.userHandle = cred.response.userHandle
            ? bufferToBase64url(cred.response.userHandle) : null;
    }
    return result;
}
```

## Managing passkeys

### List passkeys

```bash
curl http://localhost:8000/api/v1/auth/passkeys \
  -H "Authorization: Bearer <access_token>"
```

Returns a list of registered passkeys with metadata:

```json
[
  {
    "id": "550e8400-...",
    "device_name": "MacBook Pro",
    "transports": ["internal"],
    "backed_up": true,
    "created_at": "2025-01-15T10:30:00",
    "last_used_at": "2025-01-20T14:22:00"
  }
]
```

### Delete a passkey

```bash
curl -X DELETE http://localhost:8000/api/v1/auth/passkeys/550e8400-... \
  -H "Authorization: Bearer <access_token>"
```

Returns 204 on success, 404 if not found or not owned by the current user.

## Clone detection

Hardware authenticators maintain a `sign_count` that increments on each use. The library uses compare-and-swap to detect cloned authenticators:

1. On each authentication, the authenticator reports its current sign count.
2. The server only accepts the new count if it's strictly greater than the stored value (atomic CAS via `update_passkey_sign_count()`).
3. If the CAS fails and the reported count is non-zero, authentication is rejected. This means another device already used a higher count, indicating a clone.

Synced passkeys (iCloud Keychain, Google Password Manager) report `sign_count=0` and skip this check, since they're designed to exist on multiple devices.

## Configuration reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `PASSKEY_ENABLED` | bool | `False` | Enable passkey routes |
| `PASSKEY_RP_ID` | str | None | Relying party ID (bare domain, e.g. `example.com`) |
| `PASSKEY_RP_NAME` | str | None | Display name shown in browser prompts |
| `PASSKEY_ORIGINS` | list[str] | `[]` | Expected origins (e.g. `["https://example.com"]`) |
| `PASSKEY_CHALLENGE_BACKEND` | str | `"memory"` | `"memory"` or `"redis"` |
| `PASSKEY_CHALLENGE_TTL` | int | `60` | Challenge expiration in seconds |
| `PASSKEY_REQUIRE_USER_VERIFICATION` | bool | `True` | Require biometric/PIN verification |

All settings use the `FULLAUTH_` prefix as environment variables (e.g. `FULLAUTH_PASSKEY_ENABLED=true`).

## Security considerations

- **Challenge store backend**: the in-memory challenge store is per-process. In multi-worker deployments, `begin` and `complete` can hit different workers and the challenge is lost. Use `PASSKEY_CHALLENGE_BACKEND=redis` in production.

- **Rate limiting**: `authenticate/begin` and `authenticate/complete` are rate-limited by `AUTH_RATE_LIMITS.passkey_auth` (default 10 per minute per IP).

- **User verification**: `PASSKEY_REQUIRE_USER_VERIFICATION=True` (default) requires biometric or PIN confirmation on the device. Disabling it allows presence-only checks (just touching the key).

- **User enumeration**: when an email is passed to `authenticate/begin`, the response always returns an `allowCredentials` list regardless of whether the email exists. This prevents attackers from probing which emails have passkeys registered.
