from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

_argon2_hasher = PasswordHasher()
_algorithm: Literal["argon2id", "bcrypt"] = "argon2id"


def configure_hasher(algorithm: Literal["argon2id", "bcrypt"] = "argon2id") -> None:
    global _algorithm
    if algorithm == "bcrypt":
        try:
            import bcrypt  # noqa: F401
        except ImportError:
            raise ImportError(
                "bcrypt is not installed. Install it with: pip install bcrypt"
            ) from None
    _algorithm = algorithm


def hash_password(password: str) -> str:
    if _algorithm == "bcrypt":
        import bcrypt

        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return _argon2_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if _algorithm == "bcrypt" or hashed.startswith("$2b$"):
        try:
            import bcrypt

            return bcrypt.checkpw(plain.encode(), hashed.encode())
        except ImportError:
            return False
    try:
        return _argon2_hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    if hashed.startswith("$2b$"):
        return _algorithm != "bcrypt"
    return _argon2_hasher.check_needs_rehash(hashed)
