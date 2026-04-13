# Password Validation

fastapi-fullauth includes a configurable password validator that checks passwords on registration, password change, and password reset.

## Default behavior

By default, only minimum length is enforced (8 characters, configurable via `PASSWORD_MIN_LENGTH`).

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
    config=FullAuthConfig(
        SECRET_KEY="...",
    ),
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

## Password hashing

Passwords are hashed with **Argon2id** by default. Switch to bcrypt via config:

```python
fullauth = FullAuth(
    adapter=adapter,
    config=FullAuthConfig(
        SECRET_KEY="...",
        PASSWORD_HASH_ALGORITHM="bcrypt",  # requires: pip install bcrypt
    ),
)
```

When switching algorithms, existing hashes are transparently detected by prefix (`$2b$` for bcrypt, `$argon2` for Argon2id). Users are rehashed on their next successful login.
