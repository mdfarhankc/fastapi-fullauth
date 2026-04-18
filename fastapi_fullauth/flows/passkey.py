"""Passkey (WebAuthn) registration and authentication flows."""

import logging
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from uuid import UUID

from uuid_utils import uuid7

from fastapi_fullauth.adapters.base import AbstractUserAdapter, PasskeyAdapterMixin
from fastapi_fullauth.core.challenges import ChallengeStore
from fastapi_fullauth.types import PasskeyCredential, TokenPair, UserID, UserSchema

logger = logging.getLogger("fastapi_fullauth.passkey")


def _b64_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    return urlsafe_b64decode(data + "=" * padding)


async def begin_registration(
    user: UserSchema,
    rp_id: str,
    rp_name: str,
    challenge_store: ChallengeStore,
    adapter: PasskeyAdapterMixin,
    challenge_ttl: int = 60,
) -> dict:
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

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=user.email,
        user_id=str(user.id).encode(),
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    challenge_key = f"passkey:reg:{secrets.token_hex(16)}"
    await challenge_store.store(challenge_key, _b64_encode(options.challenge), ttl=challenge_ttl)

    import json

    options_json = json.loads(options_to_json(options))
    options_json["challenge_key"] = challenge_key
    return options_json


async def complete_registration(
    challenge_key: str,
    credential: dict,
    device_name: str,
    user: UserSchema,
    rp_id: str,
    expected_origin: str | list[str],
    challenge_store: ChallengeStore,
    adapter: PasskeyAdapterMixin,
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
    challenge_ttl: int = 60,
) -> dict:
    """Generate WebAuthn authentication options.

    If user_id is provided, sends allowCredentials for that user (non-discoverable).
    If user_id is None, allows discoverable credentials (true passwordless).
    """
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    allow_credentials = None
    if user_id is not None and adapter is not None:
        existing = await adapter.get_user_passkeys(user_id)
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=_b64_decode(pk.credential_id),
                transports=pk.transports if pk.transports else None,
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

    options_json = json.loads(options_to_json(options))
    options_json["challenge_key"] = challenge_key
    return options_json


async def complete_authentication(
    challenge_key: str,
    credential: dict,
    rp_id: str,
    expected_origin: str | list[str],
    challenge_store: ChallengeStore,
    adapter: AbstractUserAdapter,
    passkey_adapter: PasskeyAdapterMixin,
    token_engine,
) -> tuple[TokenPair, UserSchema]:
    """Verify WebAuthn authentication response and issue JWT tokens."""
    from webauthn import verify_authentication_response

    from fastapi_fullauth.types import RefreshToken

    challenge_b64 = await challenge_store.pop(challenge_key)
    if challenge_b64 is None:
        raise ValueError("Challenge expired or invalid")

    expected_challenge = _b64_decode(challenge_b64)

    credential_id_b64 = credential.get("id", "")
    stored = await passkey_adapter.get_passkey_by_credential_id(credential_id_b64)
    if stored is None:
        raise ValueError("Unknown passkey credential")

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        credential_public_key=_b64_decode(stored.public_key),
        credential_current_sign_count=stored.sign_count,
    )

    await passkey_adapter.update_passkey_sign_count(
        stored.credential_id, verification.new_sign_count
    )

    user = await adapter.get_user_by_id(stored.user_id)
    if user is None or not user.is_active:
        raise ValueError("User not found or inactive")

    uid = str(user.id)
    roles = await adapter.get_user_roles(user.id)
    access, refresh_meta = token_engine.create_token_pair(user_id=uid, roles=roles)

    await adapter.store_refresh_token(
        RefreshToken(
            token=refresh_meta.token,
            user_id=uid,
            expires_at=refresh_meta.expires_at,
            family_id=refresh_meta.family_id,
        )
    )

    token_pair = TokenPair(
        access_token=access,
        refresh_token=refresh_meta.token,
        expires_in=token_engine.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    logger.info("Passkey authentication: user_id=%s", user.id)
    return token_pair, user
