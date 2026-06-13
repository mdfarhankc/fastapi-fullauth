"""Passkey (WebAuthn) registration and authentication flows."""

import logging
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import TYPE_CHECKING, Any
from uuid import UUID

from uuid_utils import uuid7

from fastapi_fullauth.adapters.base import AbstractUserAdapter, PasskeyAdapterMixin
from fastapi_fullauth.protection.challenges import ChallengeStore
from fastapi_fullauth.types import PasskeyCredential, TokenPair, UserID, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.core.tokens import TokenEngine

logger = logging.getLogger("fastapi_fullauth.passkey")


def _b64_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    padding = (-len(data)) % 4
    return urlsafe_b64decode(data + "=" * padding)


async def begin_registration(
    user: UserSchema,
    rp_id: str,
    rp_name: str,
    challenge_store: ChallengeStore,
    adapter: PasskeyAdapterMixin,
    challenge_ttl: int = 60,
    require_user_verification: bool = True,
) -> dict[str, Any]:
    """Generate WebAuthn registration options for a logged-in user."""
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    existing = await adapter.get_user_passkeys(user.id)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=_b64_decode(pk.credential_id)) for pk in existing
    ]

    uv = (
        UserVerificationRequirement.REQUIRED
        if require_user_verification
        else UserVerificationRequirement.PREFERRED
    )
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=user.email,
        user_id=str(user.id).encode(),
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=uv,
        ),
    )

    challenge_key = f"passkey:reg:{secrets.token_hex(16)}"
    await challenge_store.store(challenge_key, _b64_encode(options.challenge), ttl=challenge_ttl)

    import json

    options_json: dict[str, Any] = json.loads(options_to_json(options))
    options_json["challenge_key"] = challenge_key
    return options_json


async def complete_registration(
    challenge_key: str,
    credential: dict[str, Any],
    device_name: str,
    user: UserSchema,
    rp_id: str,
    expected_origin: str | list[str],
    challenge_store: ChallengeStore,
    adapter: PasskeyAdapterMixin,
    require_user_verification: bool = True,
) -> PasskeyCredential:
    """Verify WebAuthn registration response and store the credential."""
    from webauthn import verify_registration_response

    challenge_b64 = await challenge_store.pop(challenge_key)
    if challenge_b64 is None:
        raise ValueError("Challenge expired or invalid")

    expected_challenge = _b64_decode(challenge_b64)

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        require_user_verification=require_user_verification,
    )

    transports = []
    if isinstance(credential, dict) and "response" in credential:
        transports = credential["response"].get("transports", [])

    passkey = PasskeyCredential(
        id=UUID(str(uuid7())),
        user_id=user.id,
        credential_id=_b64_encode(verification.credential_id),
        public_key=_b64_encode(verification.credential_public_key),
        sign_count=verification.sign_count,
        device_name=device_name,
        transports=transports,
        backed_up=verification.credential_backed_up,
    )

    await adapter.store_passkey(passkey)
    logger.info("Passkey registered: user_id=%s, device=%s", user.id, device_name)
    return passkey


async def begin_authentication(
    rp_id: str,
    challenge_store: ChallengeStore,
    adapter: PasskeyAdapterMixin | None = None,
    user_id: UserID | None = None,
    email_provided: bool = False,
    challenge_ttl: int = 60,
) -> dict[str, Any]:
    """Generate WebAuthn authentication options.

    If ``email_provided`` is True, ``allowCredentials`` is always a list (possibly
    empty) so callers can't distinguish unknown emails from known ones with no
    passkeys. Without an email, allows discoverable credentials (true passwordless).
    """
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import AuthenticatorTransport, PublicKeyCredentialDescriptor

    allow_credentials: list[PublicKeyCredentialDescriptor] | None = None
    if email_provided:
        allow_credentials = []
        if user_id is not None and adapter is not None:
            existing = await adapter.get_user_passkeys(user_id)
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=_b64_decode(pk.credential_id),
                    transports=(
                        [AuthenticatorTransport(t) for t in pk.transports]
                        if pk.transports
                        else None
                    ),
                )
                for pk in existing
            ]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
    )

    challenge_key = f"passkey:auth:{secrets.token_hex(16)}"
    await challenge_store.store(challenge_key, _b64_encode(options.challenge), ttl=challenge_ttl)

    import json

    options_json: dict[str, Any] = json.loads(options_to_json(options))
    options_json["challenge_key"] = challenge_key
    return options_json


async def complete_authentication(
    challenge_key: str,
    credential: dict[str, Any],
    rp_id: str,
    expected_origin: str | list[str],
    challenge_store: ChallengeStore,
    adapter: AbstractUserAdapter,
    passkey_adapter: PasskeyAdapterMixin,
    token_engine: "TokenEngine",
    require_user_verification: bool = True,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> tuple[TokenPair, UserSchema]:
    """Verify WebAuthn authentication response and issue JWT tokens."""
    from webauthn import verify_authentication_response

    from fastapi_fullauth.flows.tokens import issue_token_pair

    challenge_b64 = await challenge_store.pop(challenge_key)
    if challenge_b64 is None:
        raise ValueError("Challenge expired or invalid")

    expected_challenge = _b64_decode(challenge_b64)

    credential_id_b64 = credential.get("id", "")
    stored = await passkey_adapter.get_passkey_by_credential_id(credential_id_b64)
    if stored is None:
        raise ValueError("Unknown passkey credential")

    # If the authenticator returned a userHandle (discoverable credentials always do),
    # it must match the user the credential is stored against. This is the server-side
    # check that the credential and account binding agree, not just our DB mapping.
    user_handle_b64 = (credential.get("response") or {}).get("userHandle")
    if user_handle_b64:
        try:
            user_handle = _b64_decode(user_handle_b64)
        except Exception as e:
            raise ValueError("Invalid passkey credential") from e
        if user_handle != str(stored.user_id).encode():
            raise ValueError("Invalid passkey credential")

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        credential_public_key=_b64_decode(stored.public_key),
        credential_current_sign_count=stored.sign_count,
        require_user_verification=require_user_verification,
    )

    # Compare-and-swap: the adapter only advances sign_count when the new value is
    # strictly greater than what's stored. If the CAS fails AND the authenticator
    # reported a non-zero counter, treat it as a clone/race and reject. A returned
    # counter of 0 means the authenticator doesn't maintain one (e.g. synced passkeys).
    advanced = await passkey_adapter.update_passkey_sign_count(
        stored.credential_id, verification.new_sign_count
    )
    if not advanced and verification.new_sign_count > 0:
        raise ValueError("Invalid passkey credential")

    user = await adapter.get_user_by_id(stored.user_id)
    if user is None or not user.is_active:
        raise ValueError("User not found or inactive")

    token_pair = await issue_token_pair(
        adapter, token_engine, user, user_agent=user_agent, ip_address=ip_address
    )

    logger.info("Passkey authentication: user_id=%s", user.id)
    return token_pair, user
