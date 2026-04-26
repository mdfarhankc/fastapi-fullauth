# Passkeys (WebAuthn)

Passwordless authentication backed by a platform authenticator (Touch ID, Face ID, Windows Hello, iCloud Keychain, Google Password Manager) or a roaming authenticator (YubiKey, etc.).

## Feature matrix

- **Config:** `PASSKEY_ENABLED=True`, `PASSKEY_RP_ID`, `PASSKEY_ORIGINS`
- **Adapter mixin:** `PasskeyAdapterMixin`
- **Router:** `passkey`
- **Extra:** `fastapi-fullauth[passkey]` (pulls in `webauthn>=2.0`)
- **Tables:** `fullauth_passkeys` — registered only when `models/passkey.py` is imported
- **Challenge store:** `PASSKEY_CHALLENGE_BACKEND` (`memory` or `redis`)

## Setup

```python
# models imports
from fastapi_fullauth.adapters.sqlmodel.models.passkey import PasskeyRecord  # noqa: F401
```

```bash
export FULLAUTH_PASSKEY_ENABLED=true
export FULLAUTH_PASSKEY_RP_ID=app.example.com
export FULLAUTH_PASSKEY_ORIGINS='["https://app.example.com"]'
export FULLAUTH_PASSKEY_CHALLENGE_BACKEND=redis   # required for multi-worker
```

`PASSKEY_RP_ID` is the **Relying Party ID** — bare hostname, no scheme, no path, no port. Passkeys registered under one RP ID can't be used on a different one. Plan this carefully: changing it after users have registered invalidates their passkeys.

`PASSKEY_ORIGINS` is the list of full origins where your frontend runs — `scheme://host[:port]`. Multiple entries for dev + staging + prod are allowed.

## Routes

- `POST /api/v1/auth/passkeys/register/begin` (auth required) — returns WebAuthn creation options + a `challenge_key`
- `POST /api/v1/auth/passkeys/register/complete` (auth required) — verifies the attestation, stores the credential
- `POST /api/v1/auth/passkeys/authenticate/begin` (public, rate-limited) — returns WebAuthn request options + a `challenge_key`
- `POST /api/v1/auth/passkeys/authenticate/complete` (public) — verifies the assertion, returns login tokens
- `GET  /api/v1/auth/passkeys` (auth required) — list current user's passkeys
- `DELETE /api/v1/auth/passkeys/{id}` (auth required) — delete one

## The typical browser flow

Register a new passkey (user is already logged in):

```js
// 1. Ask server for creation options
const begin = await fetch("/api/v1/auth/passkeys/register/begin", {
  method: "POST",
  headers: { authorization: `Bearer ${accessToken}` },
}).then(r => r.json());

// 2. Prompt authenticator
const credential = await navigator.credentials.create({
  publicKey: decodeOptions(begin),   // base64url → ArrayBuffer conversions
});

// 3. Send attestation back
await fetch("/api/v1/auth/passkeys/register/complete", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
  body: JSON.stringify({
    challenge_key: begin.challenge_key,
    credential: serializeCredential(credential),
    device_name: "Laptop — Touch ID",
  }),
});
```

Authenticate (no login required):

```js
const begin = await fetch("/api/v1/auth/passkeys/authenticate/begin", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({}),   // optional {email} for non-discoverable flow
}).then(r => r.json());

const assertion = await navigator.credentials.get({
  publicKey: decodeOptions(begin),
});

const login = await fetch("/api/v1/auth/passkeys/authenticate/complete", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    challenge_key: begin.challenge_key,
    credential: serializeCredential(assertion),
  }),
});
// → {access_token, refresh_token, ...}
```

## Native mobile apps (iOS / Android)

Passkeys are cross-platform by design. One RP ID, one passkey per user, usable on web and native apps — if you set up the domain-association files correctly. A user who enrolls a passkey on their phone can sign in on the web, and vice versa.

### RP ID choice matters more on mobile

Public-suffix domains (`*.vercel.app`, `*.netlify.app`, `*.github.io`, `*.herokuapp.com`) can host a web-only passkey setup, but they're a poor fit for native apps:

- Apple and Google want a stable, verifiable domain serving association JSON. Vercel preview URLs change per deployment.
- Public Suffix List (PSL) rules prevent using the parent (e.g. `vercel.app` itself as RP ID) — browsers reject it outright per the WebAuthn spec, and mobile SDKs follow the same rule.
- Some enterprise device-management policies block passkey enrollment on public-suffix domains.

For anything shipping to the App Store or Play Store: **use a custom domain you control.** This is also the only way to extend later with multiple frontends (`app.example.com`, `admin.example.com`) sharing one passkey via RP ID `example.com`.

### Association files

Two static JSON files, served over HTTPS from the RP ID root, prove your app is authorised to use credentials scoped to that domain.

**iOS — `https://<rp-id>/.well-known/apple-app-site-association`**

```json
{
  "webcredentials": {
    "apps": ["<TEAMID>.<bundle-id>"]
  }
}
```

`TEAMID` is your Apple Developer team ID (10 chars). `bundle-id` must match the iOS app bundle identifier. Content-Type `application/json`, no `.json` extension on the URL path. Apple caches this aggressively — use a rollout plan for changes.

**Android — `https://<rp-id>/.well-known/assetlinks.json`**

```json
[{
  "relation": ["delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "android_app",
    "package_name": "<package-id>",
    "sha256_cert_fingerprints": ["<SHA-256 fingerprint of signing cert>"]
  }
}]
```

The fingerprint must come from the signing certificate that Play Store uses — for apps enrolled in **Play App Signing** that's the app-signing-key fingerprint from the Play Console, **not** the upload keystore. Getting this wrong is the most common reason Android passkey enrolment silently fails.

### `PASSKEY_ORIGINS` entries for native apps

Beyond the web origin, add per-platform entries:

```bash
export FULLAUTH_PASSKEY_RP_ID=app.example.com
export FULLAUTH_PASSKEY_ORIGINS='[
  "https://app.example.com",
  "android:apk-key-hash:AbCdEf1234..."
]'
```

- **iOS** sends `origin: https://<rp-id>` in the clientDataJSON — same as a browser. The web origin entry covers iOS ceremonies; no extra entry needed.
- **Android** sends `origin: android:apk-key-hash:<base64url(SHA-256 of signing cert)>`. This must be in `PASSKEY_ORIGINS` or the assertion is rejected in origin validation.

Get the Android hash:

```bash
# From the signing keystore (upload or Play App Signing):
keytool -list -v -keystore release.jks -alias <alias> | grep SHA256
# Then base64url-encode the SHA-256 (strip colons, hex → bytes → b64url).
```

Or pull it straight from the Play Console under **Release → Setup → App integrity → App signing**.

### Flutter client setup

**iOS (Flutter iOS target):**
- Add the `com.apple.developer.associated-domains` entitlement in `ios/Runner/Runner.entitlements`:
  ```xml
  <key>com.apple.developer.associated-domains</key>
  <array>
    <string>webcredentials:app.example.com</string>
  </array>
  ```
- Use a Flutter passkey plugin (e.g. [`passkeys`](https://pub.dev/packages/passkeys)) that bridges to `ASAuthorizationPlatformPublicKeyCredentialProvider` on iOS 16+.

**Android (Flutter Android target):**
- Minimum API 28 (Android 9) for Credential Manager with back-compat via `androidx.credentials:credentials`.
- No manifest changes needed — the `assetlinks.json` + signing fingerprint is the binding.
- The same Flutter plugin will dispatch to Credential Manager on Android.

### End-to-end flow is identical

The library doesn't care whether the ceremony came from a browser, iOS, or Android — once the origin validates and the attestation/assertion verifies, the stored `PasskeyRecord` is platform-agnostic. A user can register on mobile and authenticate on web using the same passkey (synced via iCloud Keychain or Google Password Manager) without any special server-side handling.

### Common pitfalls

- **Android fingerprint mismatch** — you put the upload-keystore fingerprint in `assetlinks.json` but Play App Signing re-signs. Always use the Play-console-displayed fingerprint.
- **AASA served with wrong content-type** — some static hosts serve `.well-known/apple-app-site-association` as `text/html`. Apple silently rejects it. Force `application/json`.
- **RP ID case mismatch** — `Example.com` in config, `example.com` in association file. DNS is case-insensitive but these string comparisons aren't. Keep everything lowercase.
- **Preview deployment URLs** — Vercel preview (`pr-123-myapp.vercel.app`) won't match RP ID `myapp.com`. Either exclude previews from passkey flows or route `app.example.com` → production only.

## User verification (UV) is required by default

`PASSKEY_REQUIRE_USER_VERIFICATION=True` (default). Both `register/begin` and `authenticate/begin` request `UserVerificationRequirement.REQUIRED` from the authenticator, and both `register/complete` and `authenticate/complete` pass `require_user_verification=True` into the webauthn library's verify call.

**What this guarantees:** the authenticator must prove user presence — a fingerprint, a Face ID scan, a PIN, whatever it supports. The UV flag on the assertion is checked server-side against the options, and a passkey signed without UV is rejected.

**What it prevents:** a stolen unlocked laptop silently signing assertions without prompting the user, or a buggy/hostile authenticator skipping the prompt. Passkeys with UV are two-factor (device + biometric/PIN); passkeys without UV collapse to single-factor.

Don't flip `PASSKEY_REQUIRE_USER_VERIFICATION=False` unless you're deliberately accepting that trade-off.

## Discoverable credentials (usernameless flow)

The library supports both flows:

- **Non-discoverable:** `/authenticate/begin` is called with `{email: "..."}`. The server loads the user's passkey IDs and includes them as `allowCredentials` in the options. The user's authenticator narrows by ID, prompts for UV.
- **Discoverable:** `/authenticate/begin` with empty body. `allowCredentials` is empty. The authenticator shows the user all passkeys it has for this RP ID and lets them pick.

The discoverable flow is what enables true "no username typed" login. Both flows pass through `PASSKEY_REQUIRE_USER_VERIFICATION`.

## `userHandle` validation on authenticate

When the assertion returns a `userHandle` (always for discoverable credentials), the server verifies it equals the `user_id` stored on the credential row. If they mismatch, the request is rejected with a generic "invalid passkey credential" error.

This closes a class of bug where the DB's credential→user mapping can drift from what the authenticator thinks is true (data migrations, manual admin edits, etc.). The `userHandle` is cryptographically bound inside the signed assertion — it's the one thing an attacker couldn't forge.

## Sign count = clone detection

On every authentication, the authenticator increments its sign count and the server's `update_passkey_sign_count` advances the stored value via compare-and-swap:

```
UPDATE passkeys SET sign_count = :new, last_used_at = now()
WHERE credential_id = :cid AND sign_count < :new
```

If `rowcount == 0` (someone else already wrote a ≥ value), the router rejects the assertion as "invalid." Two requests that both read a stale counter can no longer both succeed.

Synced passkeys (iCloud Keychain, Google Password Manager) often keep sign count at 0 permanently. The library handles this: when the returned `new_sign_count` is 0, the CAS is expected to fail and the login proceeds regardless (no counter to compare). Only non-zero counters drive clone detection.

## Challenge store

Each begin/complete pair shares a random `challenge_key`. The challenge itself is stored server-side for up to `PASSKEY_CHALLENGE_TTL` seconds (default 60). `complete` pops it — the same challenge cannot be popped twice.

- `PASSKEY_CHALLENGE_BACKEND="memory"` — per-process `dict`, guarded by an `asyncio.Lock` for single-use correctness within one worker. **Breaks under multi-worker deployments** — register/begin on worker A and register/complete on worker B see different stores, and complete returns "challenge expired or invalid."
- `PASSKEY_CHALLENGE_BACKEND="redis"` — `GETDEL`-based atomic pop, safe across workers. Requires `REDIS_URL` and the `[redis]` extra.

Use Redis in production. The library emits a startup `UserWarning` when `PASSKEY_ENABLED=True` and `PASSKEY_CHALLENGE_BACKEND="memory"`.

## Rate limiting `authenticate/begin`

`authenticate/begin` is unauthenticated and issues a fresh challenge every call. It's rate-limited by `AUTH_RATE_LIMIT_PASSKEY_AUTH` (default 10 req/min per IP) — without it an attacker could flood the challenge store.

Registering passkeys isn't rate-limited (register endpoints require auth; the authenticated identity is the rate limit key).

## Managing passkeys from the UI

`GET /passkeys` returns the current user's passkey list:

```json
[
  {
    "id": "...",
    "device_name": "MacBook — Touch ID",
    "transports": ["internal", "hybrid"],
    "backed_up": true,
    "created_at": "...",
    "last_used_at": "..."
  }
]
```

`DELETE /passkeys/{id}` removes one. The router verifies ownership before deleting — user A can't delete user B's passkey.

**Policy gap:** deleting the last passkey when the user has no password locks them out silently. The library doesn't refuse that delete — add a confirmation on the frontend if your UX wants to.

## Migrations note

The `fullauth_passkeys` table registers only when `models/passkey.py` is imported. Apps without passkeys never get the table. Apps that enable passkeys later must re-run autogenerate after adding the import, otherwise the ORM will fail at runtime referencing a nonexistent table.
