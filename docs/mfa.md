# Two-Factor Authentication (TOTP)

A second factor on top of the password: the six-digit codes an authenticator app
such as Google Authenticator, 1Password or Aegis produces. Off by default.

## Installation

```bash
pip install "fastapi-fullauth[mfa]"
```

## Configuration

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    MFA_ISSUER="Acme",  # the name shown beside the code in the app
)
```

Setting `MFA_ISSUER` is taken as opting in, so `MFA_ENABLED` becomes `True` on its
own. Set `MFA_ENABLED=False` explicitly to configure it while keeping the routes
off.

Your adapter needs the MFA model, exactly like passkeys:

```python
from fastapi_fullauth.models.sqlmodel import MFAMixin

class MFA(MFAMixin, table=True):
    pass

adapter = SQLModelAdapter(session_maker, user_model=User, refresh_token_model=RefreshToken, mfa_model=MFA)
```

Without it the routes are not mounted, sign-in never asks for a code, and a
warning says so at startup.

## Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/auth/mfa` | session | Whether it is on, and how many recovery codes remain |
| `POST` | `/auth/mfa/enroll` | session + recent | Start enrolment; returns the secret and provisioning URI |
| `POST` | `/auth/mfa/confirm` | session | Finish enrolment with a code; returns the recovery codes |
| `DELETE` | `/auth/mfa` | session + recent | Turn it off |
| `POST` | `/auth/mfa/verify` | pending token | Exchange a code for the real token pair |

"Recent" means the same proof `DELETE /me` asks for: the current password in the
body, or a session whose credentials were checked within `REAUTH_MAX_AGE_SECONDS`.
Adding and removing a second factor are account-security actions.

## Enrolling

```
POST /api/v1/auth/mfa/enroll
Authorization: Bearer <access token>
```

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "provisioning_uri": "otpauth://totp/Acme:user@example.com?secret=...&issuer=Acme"
}
```

Render the URI as a QR code, or show the secret for manual entry. Nothing is live
yet: the secret does nothing until a code proves the authenticator was set up,
so an abandoned enrolment cannot lock anyone out. Starting again simply replaces
it.

```
POST /api/v1/auth/mfa/confirm
{"code": "123456"}
```

```json
{"recovery_codes": ["a1b2-c3d4-e5f6", "..."]}
```

!!! warning "Show the recovery codes once"
    They are stored hashed and cannot be shown again. Each one works instead of a
    code, one time, for a user who has lost their authenticator. Tell the user to
    save them before they close the page.

## Signing in

A correct password on an account with a second factor answers `202` instead of
`200`, with a short-lived token rather than a session:

```json
{"mfa_required": true, "mfa_token": "eyJhbGciOi..."}
```

That token buys the right to submit a code and nothing else: it is rejected
everywhere a session token is expected. Exchange it:

```
POST /api/v1/auth/mfa/verify
{"mfa_token": "eyJhbGciOi...", "code": "123456"}
```

The response is an ordinary login response, with the access and refresh tokens.
A recovery code goes in the same `code` field.

### Client changes

```javascript
const r = await fetch("/api/v1/auth/login", { method: "POST", body: ... });
const data = await r.json();

if (r.status === 202) {
  const code = await promptForCode();
  const verified = await fetch("/api/v1/auth/mfa/verify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ mfa_token: data.mfa_token, code }),
  });
  return verified.json();
}
return data;
```

## What is defended against

- **A code used twice.** A code stays valid for its whole 30-second step, so
  anyone who reads it over a shoulder has that long to use it. Accepting one
  records its time step, and nothing at or below that step is accepted again.
  One consequence worth knowing: the code that confirms enrolment is spent, so
  signing in needs the next one.
- **Guessing.** Six digits is a small space. `/mfa/verify` has its own rate-limit
  bucket (`AUTH_RATE_LIMITS.mfa`, 5 a minute) and failures are counted against
  the account through the lockout manager, so rotating addresses does not help.
- **Clock drift.** One step either side of now is accepted, as RFC 6238
  recommends. Wider would mean more codes valid at once.
- **A pending token reused.** It is burned once it buys a session.
- **Recovery codes.** Stored hashed, single use.

## What it does not cover

**MFA gates password sign-in only.** Passkeys are already phishing-resistant, and
an OAuth provider runs its own second factor which this library cannot inspect.
An account with a passkey or a linked provider can still sign in that way without
a code, by design.

The TOTP secret is stored in plaintext, as the OAuth provider tokens are. A
database leak hands over the second factor along with everything else; see the
[threat model](security/threat-model.md).

## Event hooks

```python
@fullauth.hooks.on("after_mfa_enabled")
async def on_enabled(user):
    await audit.record(user.id, "two-factor enabled")


@fullauth.hooks.on("after_mfa_disabled")
async def on_disabled(user):
    await notify(user.email, "Two-factor authentication was turned off")
```

Both are worth sending mail about: turning a second factor off is exactly what an
attacker who has taken an account does first.

## If a user is locked out

A recovery code is the intended path. Failing that, an operator can clear the
factor directly, which returns the account to password-only sign-in:

```python
await fullauth.adapter.delete_mfa(user_id)
```

There is deliberately no route for this: it would be a way around the second
factor.
