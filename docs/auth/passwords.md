# Password Validation

fastapi-fullauth includes a configurable password validator and transparent password hashing with algorithm migration support.

## How password validation works

Password validation runs automatically during three flows:

- **Registration** - validates the password before creating the user
- **Password change** - validates the new password before updating
- **Password reset** - validates the new password before applying the reset

The validator is passed to the `FullAuth` constructor and used by all three flows. If no validator is provided, only minimum length is enforced.

## Default behavior

By default, only minimum length is enforced (8 characters, configurable via `PASSWORD_MIN_LENGTH`):

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    PASSWORD_MIN_LENGTH=12,  # default: 8
)
```

## Custom rules

```python
from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.validators import PasswordValidator

validator = PasswordValidator(
    min_length=10,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=True,
    blocked_passwords=["password123", "qwerty123"],
)

fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(SECRET_KEY="..."),
    password_validator=validator,
)
```

## Validation rules

| Rule | Default | Description |
|------|---------|-------------|
| `min_length` | `8` | Minimum password length |
| `require_uppercase` | `False` | Must contain `[A-Z]` |
| `require_lowercase` | `False` | Must contain `[a-z]` |
| `require_digit` | `False` | Must contain `[0-9]` |
| `require_special` | `False` | Must contain `[!@#$%^&*(),.?":{}|<>]` |
| `blocked_passwords` | `[]` | List of disallowed passwords (case-insensitive) |

When validation fails, a `422 Unprocessable Entity` response is returned with all violated rules:

```json
{
  "detail": "Password must be at least 10 characters; Password must contain at least one uppercase letter"
}
```

## Blocked passwords

The `blocked_passwords` parameter accepts a list of passwords that should be rejected regardless of other rules. Matching is case-insensitive.

You can load a blocklist from a file:

```python
with open("blocked_passwords.txt") as f:
    blocked = [line.strip() for line in f if line.strip()]

validator = PasswordValidator(
    min_length=10,
    blocked_passwords=blocked,
)
```

!!! tip
    NIST SP 800-63B recommends checking passwords against known breach lists. Consider using a list like the top 10,000 from SecLists or Have I Been Pwned's password corpus.

## Password hashing

### Argon2id (default)

Argon2id is the default hashing algorithm. It's memory-hard, making it resistant to GPU and ASIC attacks. It's the OWASP recommended algorithm for new applications.

### Bcrypt

Bcrypt is supported as an alternative:

```python
config = FullAuthConfig(
    SECRET_KEY="...",
    PASSWORD_HASH_ALGORITHM="bcrypt",
)
```

!!! warning
    Bcrypt silently truncates passwords longer than 72 bytes. The library rejects passwords that would be truncated, returning a validation error.

### Transparent rehashing

When a user logs in, the library checks if the stored hash uses the currently configured algorithm. If it doesn't (e.g. you switched from bcrypt to argon2id), the password is rehashed automatically after successful verification.

This runs in a try/except so a transient database error during rehashing doesn't block a successful login. The user logs in either way; the rehash is retried on the next login.

### OAuth-only users

Users created through OAuth login have no password hash (`hashed_password=NULL`). They can set a password later through the password change endpoint.

## Password change flow

`POST /change-password` performs these steps:

1. Verify the current password (skipped if the user has no existing password, e.g. OAuth-only users)
2. Validate the new password against the password validator
3. Hash and store the new password
4. Revoke all refresh tokens (forces re-login on all devices)
5. Fire the `after_password_change` hook

## Password reset flow

Password reset is a two-step flow:

**Step 1: Request reset** (`POST /password-reset/request`)

1. Look up the user by email
2. Generate a purpose-scoped JWT with `purpose=password_reset` and a short TTL (default 15 minutes)
3. Fire the `send_password_reset_email` hook with the email and token
4. Return 202 regardless of whether the email exists (prevents enumeration)

**Step 2: Confirm reset** (`POST /password-reset/confirm`)

1. Verify the reset token (signature, expiry, purpose)
2. Validate the new password
3. Hash and store the new password
4. Blacklist the reset token (prevents reuse)
5. Revoke all refresh tokens (forces re-login on all devices)
6. Fire the `after_password_reset` hook
