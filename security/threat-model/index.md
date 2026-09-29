# Threat Model

This page describes what fastapi-fullauth defends against, the assumptions those defenses rest on, and what remains your application's responsibility. Report suspected vulnerabilities as described in [SECURITY.md](https://github.com/mdfarhankc/fastapi-fullauth/blob/main/SECURITY.md).

## Assets

- **Credentials:** password hashes, passkey public keys, OAuth identities.
- **Session tokens:** access tokens (short-lived JWTs) and refresh tokens (long-lived, rotated).
- **Single-use tokens:** email-verification, password-reset, and OAuth state tokens.
- **Account state:** verification status, roles and permissions, superuser flag.

## Trust assumptions

The defenses below hold only if these are true:

- **`SECRET_KEY` stays secret.** Anyone holding it can mint any token. Rotating it invalidates every token.
- **Transport is HTTPS.** Tokens and cookies are bearer credentials.
- **Proxy headers are configured to match your deployment.** `TRUSTED_PROXY_HEADERS` and `TRUSTED_PROXY_COUNT` decide which client IP rate limiting and lockout see; a wrong value lets clients spoof their address.
- **Shared state is shared.** With more than one worker, the token blacklist, lockout, rate limits, and passkey challenges must use Redis. In-memory backends only know about events in their own process.
- **Your database and Redis are not attacker-controlled.**

## Threats and mitigations

| Threat                                                             | Mitigation                                                                                                                                                                   |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Password guessing                                                  | Argon2id (or bcrypt) hashing off the event loop, per-account lockout keyed on the normalised identifier, per-IP rate limits on auth routes                                   |
| Discovering which emails are registered                            | Identical responses and matched hashing cost for new and duplicate registrations, email hooks run after the response, dummy password verification for unknown users at login |
| Stolen access token                                                | Short lifetime; logout, device revoke, password change, and password reset revoke the whole session, including access tokens it already issued                               |
| Stolen refresh token                                               | Stored only as a SHA-256 digest; rotation on every use; replaying a rotated token revokes the entire session family                                                          |
| Leaked database or backup                                          | Refresh tokens are digests and passwords are slow hashes, so neither can be replayed directly                                                                                |
| Token confusion (using a reset or verification token as a session) | Tokens carry a type and a purpose, and every consumer checks both; single-use tokens are burned after use                                                                    |
| OAuth login CSRF / account fixation                                | The OAuth `state` is bound to the client that started the login through a `binding` secret, as RFC 9700 requires; state is single-use                                        |
| OAuth account takeover via an unverified provider email            | Automatic linking to an existing account only when the provider reports the email as verified                                                                                |
| Passkey cloning or replay                                          | Single-use challenges, sign-count compare-and-swap, userHandle must match the stored credential's account                                                                    |
| Mass assignment                                                    | Profile updates filter protected fields and validate against the user schema; user creation never persists privileged fields                                                 |
| CSRF on cookie sessions                                            | Opt-in `CSRFMiddleware` (signed double-submit token, optional origin check)                                                                                                  |

## Deliberate failure modes

Some backends must choose between availability and strictness when Redis is unreachable:

- **Token blacklist fails closed.** If revocation cannot be checked, the token is rejected. A Redis outage signs users out rather than letting revoked tokens through.
- **Rate limiter fails open.** Requests are allowed and the error is logged. A Redis outage must not lock every user out of login.
- **Account lockout fails open.** Attempts are neither counted nor blocked while Redis is unreachable, and the error is logged. Failing closed would lock every account out, and raising would turn every login into a 500; brute-force protection is lost for the duration.

## Destructive actions require recent authentication

Deleting an account and setting a first password on an account that has none both require proof that the person is present, not just that a session exists: either the current password, or credentials checked within `REAUTH_MAX_AGE_SECONDS` (5 minutes by default). The age comes from an `auth_time` claim stamped when credentials are checked and carried unchanged through refresh rotation, so refreshing a stolen token does not renew it.

## Your application's responsibilities

- **Cross-site scripting.** Any token readable by JavaScript can be stolen by XSS. Prefer the cookie backend with `CSRFMiddleware` for browser apps, and use a Content Security Policy.
- **Email delivery.** Verification and reset tokens are only as safe as the channel you send them over.
- **Authorization in your own routes.** The dependencies authenticate users and check roles and permissions; deciding who may act on which resource is up to you.
- **Secrets and infrastructure.** Key management, TLS, and database access control.

## Known limitations

These are tracked for future releases:

- OAuth provider access and refresh tokens are stored in plaintext.
- Tokens carry no `iss` or `aud` claim, so services sharing a `SECRET_KEY` accept each other's tokens.
- Pruning expired refresh tokens is available (`adapter.prune_expired_refresh_tokens()`) but has to be scheduled by the application; nothing runs it for you.
- A password-reset link is invalidated by a password change, but not by a later reset *request*: the newest link and any still-unused older one both work until one of them is used.
