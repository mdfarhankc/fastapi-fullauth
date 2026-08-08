import hashlib
from typing import Any, Literal

from anyio import to_thread
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from fastapi_fullauth.exceptions import InvalidPasswordError

_argon2_hasher = PasswordHasher()


def hash_refresh_token(token: str) -> str:
    """Deterministic digest for storing refresh tokens at rest.

    Refresh tokens are high-entropy, so an unsalted sha256 is sufficient (there
    is no dictionary to attack) and keeps lookups an exact-match query. A leaked
    database then exposes only digests, which cannot be replayed as tokens.
    """
    return hashlib.sha256(token.encode()).hexdigest()


_BCRYPT_MAX_BYTES = 72
# bcrypt hashes from other implementations or older versions use $2a$/$2y$;
# recognize all of them so imported password stores keep verifying
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


def _import_bcrypt() -> Any:
    """Import bcrypt, raising an install hint when the optional extra is missing."""
    try:
        import bcrypt
    except ImportError:
        raise ImportError(
            "bcrypt is required for bcrypt password hashing/verification. "
            "Install it with: pip install fastapi-fullauth[bcrypt]"
        ) from None
    return bcrypt


def hash_password(password: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id") -> str:
    if algorithm == "bcrypt":
        # bcrypt silently truncates to 72 bytes; reject so users aren't locked out
        # the day they switch hash algorithms
        if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
            raise InvalidPasswordError(
                f"bcrypt passwords must be at most {_BCRYPT_MAX_BYTES} bytes when "
                "UTF-8 encoded. Use argon2id for longer passwords."
            )
        bcrypt = _import_bcrypt()

        hashed: bytes = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return hashed.decode()
    return _argon2_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if hashed.startswith(_BCRYPT_PREFIXES):
        # Surface a missing-bcrypt install rather than failing the login silently.
        bcrypt = _import_bcrypt()
        try:
            return bool(bcrypt.checkpw(plain.encode(), hashed.encode()))
        except ValueError:
            return False
    try:
        return _argon2_hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(
    hashed: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id"
) -> bool:
    if hashed.startswith(_BCRYPT_PREFIXES):
        return algorithm != "bcrypt"
    return _argon2_hasher.check_needs_rehash(hashed)


async def ahash_password(
    password: str, algorithm: Literal["argon2id", "bcrypt"] = "argon2id"
) -> str:
    """Async wrapper around :func:`hash_password`.

    Argon2id and bcrypt are CPU-bound and take tens to hundreds of milliseconds;
    running them inline would block the event loop and serialize every
    concurrent request. This offloads the work to a worker thread.
    """
    return await to_thread.run_sync(hash_password, password, algorithm)


async def averify_password(plain: str, hashed: str) -> bool:
    """Async wrapper around :func:`verify_password` that offloads the CPU-bound
    verification to a worker thread, keeping the event loop responsive."""
    return await to_thread.run_sync(verify_password, plain, hashed)
