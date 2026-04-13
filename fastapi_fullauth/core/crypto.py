from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

_argon2_hasher = PasswordHasher()


def hash_password(password: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id") -> str:
    if algorithm == "bcrypt":
        import bcrypt

        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return _argon2_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if hashed.startswith("$2b$"):
        try:
            import bcrypt

            return bcrypt.checkpw(plain.encode(), hashed.encode())
        except ImportError:
            return False
    try:
        return _argon2_hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError):
        return False


def password_needs_rehash(
    hashed: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id"
) -> bool:
    if hashed.startswith("$2b$"):
        return algorithm != "bcrypt"
    return _argon2_hasher.check_needs_rehash(hashed)
