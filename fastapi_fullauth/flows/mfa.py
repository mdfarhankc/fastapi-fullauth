"""TOTP second factor: enrolment, confirmation, and verification at sign-in.

A second factor is only worth having if the ways around it are closed, so three
rules shape this module:

- A secret does nothing until a first valid code confirms it, otherwise a
  half-finished enrolment would lock the account out of its own sign-in.
- A code accepted once is refused for the rest of its time step, because a code
  stays valid for thirty seconds and anyone who reads it over the user's
  shoulder has that long to use it.
- Recovery codes exist from the moment the factor goes live. Losing the phone is
  the common case, and without them it is a permanent lockout.
"""

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fastapi_fullauth.adapters.base import AbstractUserAdapter, MFAAdapterMixin
from fastapi_fullauth.exceptions import AuthenticationError
from fastapi_fullauth.types import MFACredential, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.types import UserID

logger = logging.getLogger("fastapi_fullauth.mfa")

# One step either side of now, the window RFC 6238 suggests, so a user whose
# clock drifts slightly is not locked out. Wider would mean more codes valid at
# once for an attacker to guess.
DRIFT_STEPS = 1
TIME_STEP_SECONDS = 30

RECOVERY_CODE_COUNT = 10


def generate_secret() -> str:
    import pyotp

    return str(pyotp.random_base32())


def provisioning_uri(secret: str, account_name: str, issuer: str) -> str:
    """The ``otpauth://`` URI an authenticator app reads from a QR code."""
    import pyotp

    return str(pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer))


def _hash_recovery_code(code: str) -> str:
    """Recovery codes are high-entropy, so an unsalted digest is enough.

    They are stored hashed for the same reason refresh tokens are: a database
    leak must not hand over a working way in.
    """
    return hashlib.sha256(code.encode()).hexdigest()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> tuple[list[str], list[str]]:
    """Return the plaintext codes to show once, and the digests to store."""
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(count)]
    return codes, [_hash_recovery_code(code) for code in codes]


def _counter_for(at: datetime) -> int:
    return int(at.timestamp()) // TIME_STEP_SECONDS


def _matching_counter(secret: str, code: str, now: datetime | None = None) -> int | None:
    """The time step a code belongs to, or None if it matches none of them.

    Returns the step rather than a bool because the caller has to record which
    one was used; comparing with ``hmac.compare_digest`` keeps the check free of
    a timing signal on the digits.
    """
    import pyotp

    totp = pyotp.TOTP(secret)
    at = now or datetime.now(timezone.utc)
    current = _counter_for(at)
    for offset in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        counter = current + offset
        expected = totp.generate_otp(counter)
        if hmac.compare_digest(expected, code):
            return counter
    return None


async def begin_enrollment(
    adapter: AbstractUserAdapter,
    user: UserSchema,
    issuer: str,
) -> tuple[str, str]:
    """Create an unconfirmed secret and return it with its provisioning URI.

    Replaces any unconfirmed secret, so an abandoned enrolment can simply be
    restarted. Refuses to touch a confirmed one: re-enrolling is removing the
    factor and adding it again, which is a deliberate act with its own route.
    """
    mfa_adapter = _require_mixin(adapter)
    existing = await mfa_adapter.get_mfa(user.id)
    if existing is not None and existing.is_confirmed:
        raise AuthenticationError("Two-factor authentication is already enabled")

    secret = generate_secret()
    await mfa_adapter.store_mfa(MFACredential(user_id=user.id, secret=secret))
    logger.info("MFA enrolment started: user_id=%s", user.id)
    return secret, provisioning_uri(secret, account_name=user.email, issuer=issuer)


async def confirm_enrollment(
    adapter: AbstractUserAdapter,
    user: UserSchema,
    code: str,
) -> list[str]:
    """Turn an enrolment live, returning the recovery codes to show once."""
    mfa_adapter = _require_mixin(adapter)
    credential = await mfa_adapter.get_mfa(user.id)
    if credential is None:
        raise AuthenticationError("Start enrolment before confirming it")
    if credential.is_confirmed:
        raise AuthenticationError("Two-factor authentication is already enabled")

    counter = _matching_counter(credential.secret, code)
    if counter is None:
        logger.warning("MFA enrolment confirmation failed: user_id=%s", user.id)
        raise AuthenticationError("Invalid code")

    codes, hashes = generate_recovery_codes()
    await mfa_adapter.confirm_mfa(user.id, hashes)
    await mfa_adapter.advance_mfa_counter(user.id, counter)
    logger.info("MFA enabled: user_id=%s", user.id)
    return codes


async def verify_code(
    adapter: AbstractUserAdapter,
    user_id: "UserID",
    code: str,
) -> None:
    """Accept one TOTP code or one recovery code, or raise.

    Both paths are single-use: a TOTP code advances the stored time step, and a
    recovery code is consumed. Failure says the same thing either way, so the
    response cannot be used to learn which kind was tried.
    """
    mfa_adapter = _require_mixin(adapter)
    credential = await mfa_adapter.get_mfa(user_id)
    if credential is None or not credential.is_confirmed:
        raise AuthenticationError("Invalid code")

    normalised = code.strip().replace(" ", "")

    counter = _matching_counter(credential.secret, normalised)
    if counter is not None:
        # Rejects a code already accepted in this window, and a concurrent
        # second use of it, since only one caller can move the counter.
        if not await mfa_adapter.advance_mfa_counter(user_id, counter):
            logger.warning("MFA code replayed: user_id=%s", user_id)
            raise AuthenticationError("Invalid code")
        return

    if await mfa_adapter.consume_recovery_code(user_id, _hash_recovery_code(normalised)):
        logger.warning("MFA recovery code used: user_id=%s", user_id)
        return

    logger.warning("MFA verification failed: user_id=%s", user_id)
    raise AuthenticationError("Invalid code")


async def disable(adapter: AbstractUserAdapter, user_id: "UserID") -> None:
    mfa_adapter = _require_mixin(adapter)
    await mfa_adapter.delete_mfa(user_id)
    logger.info("MFA disabled: user_id=%s", user_id)


async def is_enabled(adapter: AbstractUserAdapter, user_id: "UserID") -> bool:
    """Whether sign-in for this user has to pass a second factor."""
    if not adapter.supports_feature("mfa") or not isinstance(adapter, MFAAdapterMixin):
        return False
    credential = await adapter.get_mfa(user_id)
    return credential is not None and credential.is_confirmed


def _require_mixin(adapter: AbstractUserAdapter) -> MFAAdapterMixin:
    if not isinstance(adapter, MFAAdapterMixin):
        raise RuntimeError(
            f"Two-factor authentication needs an adapter implementing MFAAdapterMixin; "
            f"{type(adapter).__name__} does not."
        )
    return adapter
