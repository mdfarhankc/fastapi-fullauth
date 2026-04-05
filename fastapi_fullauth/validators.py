import re

from fastapi_fullauth.exceptions import InvalidPasswordError


class PasswordValidator:
    def __init__(
        self,
        min_length: int = 8,
        require_uppercase: bool = False,
        require_lowercase: bool = False,
        require_digit: bool = False,
        require_special: bool = False,
        blocked_passwords: list[str] | None = None,
    ) -> None:
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special
        self.blocked_passwords = set(p.lower() for p in (blocked_passwords or []))

    def validate(self, password: str) -> None:
        errors: list[str] = []

        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")

        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if self.require_digit and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        if self.require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")

        if password.lower() in self.blocked_passwords:
            errors.append("This password is too common")

        if errors:
            raise InvalidPasswordError("; ".join(errors))
