from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from fastapi_fullauth.exceptions import InvalidPasswordError

_argon2_hasher = PasswordHasher()

_BCRYPT_MAX_BYTES = 72


def hash_password(password: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id") -> str:
    if algorithm == "bcrypt":
        # bcrypt silently truncates to 72 bytes; reject so users aren't locked out
        # the day they switch hash algorithms
        if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
            raise InvalidPasswordError(
                f"bcrypt passwords must be at most {_BCRYPT_MAX_BYTES} bytes when "
                "UTF-8 encoded. Use argon2id for longer passwords."
            )
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
