"""Passkey (WebAuthn) flows and routes.

Cryptographic verification belongs to the webauthn library, so its verify
functions are patched here. These tests cover the logic this library adds
around them: single-use challenges, the userHandle binding, sign-count clone
detection, inactive accounts, and uniform failures on the sign-in endpoint.
"""

import base64
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.core.tokens import TokenEngine
from fastapi_fullauth.flows.passkey import (
    begin_authentication,
    begin_registration,
    complete_authentication,
    complete_registration,
)
from fastapi_fullauth.protection.challenges import InMemoryChallengeStore
from fastapi_fullauth.types import CreateUserSchema

SECRET = "test-secret-key-that-is-long-enough-32b"
RP_ID = "localhost"
ORIGIN = "http://localhost"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _registered(credential_id: bytes = b"cred-1", sign_count: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=b"public-key",
        sign_count=sign_count,
        credential_backed_up=False,
    )


def _authenticated(new_sign_count: int) -> SimpleNamespace:
    return SimpleNamespace(new_sign_count=new_sign_count)


async def _user(adapter, email="pk@test.com"):
    return await adapter.create_user(
        CreateUserSchema(email=email, password="securepass123"), hashed_password="x"
    )


async def _register_passkey(adapter, user, store, credential_id=b"cred-1", sign_count=0):
    options = await begin_registration(
        user=user, rp_id=RP_ID, rp_name="Test", challenge_store=store, adapter=adapter
    )
    with patch(
        "webauthn.verify_registration_response", return_value=_registered(credential_id, sign_count)
    ):
        return await complete_registration(
            challenge_key=options["challenge_key"],
            credential={"id": _b64(credential_id), "response": {"transports": ["internal"]}},
            device_name="Laptop",
            user=user,
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=store,
            adapter=adapter,
        )


async def _authenticate(adapter, store, credential, new_sign_count=1):
    options = await begin_authentication(rp_id=RP_ID, challenge_store=store)
    with patch(
        "webauthn.verify_authentication_response", return_value=_authenticated(new_sign_count)
    ):
        return await complete_authentication(
            challenge_key=options["challenge_key"],
            credential=credential,
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=store,
            adapter=adapter,
            passkey_adapter=adapter,
            token_engine=TokenEngine(FullAuthConfig(SECRET_KEY=SECRET)),
        )


# ── Registration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_registration_challenge_is_single_use(adapter):
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    options = await begin_registration(
        user=user, rp_id=RP_ID, rp_name="Test", challenge_store=store, adapter=adapter
    )
    kwargs = dict(
        challenge_key=options["challenge_key"],
        credential={"id": _b64(b"cred-1"), "response": {}},
        device_name="Laptop",
        user=user,
        rp_id=RP_ID,
        expected_origin=ORIGIN,
        challenge_store=store,
        adapter=adapter,
    )
    with patch("webauthn.verify_registration_response", return_value=_registered()):
        await complete_registration(**kwargs)
        with pytest.raises(ValueError, match="Challenge expired or invalid"):
            await complete_registration(**kwargs)


@pytest.mark.asyncio
async def test_registration_excludes_credentials_the_user_already_has(adapter):
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    await _register_passkey(adapter, user, store)

    options = await begin_registration(
        user=user, rp_id=RP_ID, rp_name="Test", challenge_store=store, adapter=adapter
    )
    assert [c["id"] for c in options["excludeCredentials"]] == [_b64(b"cred-1")]


# ── Authentication ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authentication_issues_tokens_and_advances_the_sign_count(adapter):
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    passkey = await _register_passkey(adapter, user, store, sign_count=3)

    tokens, signed_in = await _authenticate(
        adapter, store, {"id": passkey.credential_id, "response": {}}, new_sign_count=4
    )
    assert signed_in.id == user.id
    assert tokens.access_token and tokens.refresh_token
    stored = await adapter.get_passkey_by_credential_id(passkey.credential_id)
    assert stored.sign_count == 4


@pytest.mark.asyncio
async def test_authentication_challenge_is_single_use(adapter):
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    passkey = await _register_passkey(adapter, user, store)
    options = await begin_authentication(rp_id=RP_ID, challenge_store=store)
    kwargs = dict(
        challenge_key=options["challenge_key"],
        credential={"id": passkey.credential_id, "response": {}},
        rp_id=RP_ID,
        expected_origin=ORIGIN,
        challenge_store=store,
        adapter=adapter,
        passkey_adapter=adapter,
        token_engine=TokenEngine(FullAuthConfig(SECRET_KEY=SECRET)),
    )
    with patch("webauthn.verify_authentication_response", return_value=_authenticated(1)):
        await complete_authentication(**kwargs)
        with pytest.raises(ValueError, match="Challenge expired or invalid"):
            await complete_authentication(**kwargs)


@pytest.mark.asyncio
async def test_authentication_rejects_a_user_handle_for_another_account(adapter):
    """Discoverable credentials return a userHandle; it must name the account the
    credential is stored against, not whichever account the client claims."""
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    other = await _user(adapter, "other@test.com")
    passkey = await _register_passkey(adapter, user, store)

    forged = {"id": passkey.credential_id, "response": {"userHandle": _b64(str(other.id).encode())}}
    with pytest.raises(ValueError, match="Invalid passkey credential"):
        await _authenticate(adapter, store, forged)

    genuine = {"id": passkey.credential_id, "response": {"userHandle": _b64(str(user.id).encode())}}
    _, signed_in = await _authenticate(adapter, store, genuine)
    assert signed_in.id == user.id


@pytest.mark.asyncio
async def test_authentication_rejects_a_sign_count_that_did_not_advance(adapter):
    """A counter at or below the stored value signals a cloned authenticator."""
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    passkey = await _register_passkey(adapter, user, store, sign_count=5)

    with pytest.raises(ValueError, match="Invalid passkey credential"):
        await _authenticate(
            adapter, store, {"id": passkey.credential_id, "response": {}}, new_sign_count=3
        )


@pytest.mark.asyncio
async def test_authentication_accepts_authenticators_without_a_counter(adapter):
    """Synced passkeys always report 0; that is not a clone signal."""
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    passkey = await _register_passkey(adapter, user, store, sign_count=0)

    for _ in range(2):
        _, signed_in = await _authenticate(
            adapter, store, {"id": passkey.credential_id, "response": {}}, new_sign_count=0
        )
        assert signed_in.id == user.id


@pytest.mark.asyncio
async def test_authentication_rejects_unknown_credentials_and_inactive_users(adapter):
    store = InMemoryChallengeStore()
    user = await _user(adapter)
    passkey = await _register_passkey(adapter, user, store)

    with pytest.raises(ValueError, match="Unknown passkey credential"):
        await _authenticate(adapter, store, {"id": _b64(b"never-registered"), "response": {}})

    await adapter.update_user(user.id, {"is_active": False})
    with pytest.raises(ValueError, match="inactive"):
        await _authenticate(adapter, store, {"id": passkey.credential_id, "response": {}})


# ── Routes ───────────────────────────────────────────────────────────


@pytest.fixture
def passkey_app(adapter):
    config = FullAuthConfig(
        SECRET_KEY=SECRET,
        PREVENT_REGISTRATION_ENUMERATION=False,
        PASSKEY_RP_ID=RP_ID,
        PASSKEY_ORIGINS=[ORIGIN],
    )
    app = FastAPI()
    FullAuth(config=config, adapter=adapter).init_app(app)
    return app


@pytest.mark.asyncio
async def test_passkey_routes_register_then_sign_in(passkey_app):
    transport = ASGITransport(app=passkey_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/v1/auth/passkeys/register/begin")
        assert r.status_code == 401

        body = {"email": "pk@test.com", "password": "securepass123"}
        await client.post("/api/v1/auth/register", json=body)
        login = await client.post("/api/v1/auth/login", json=body)
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        options = (
            await client.post("/api/v1/auth/passkeys/register/begin", headers=headers)
        ).json()
        with patch("webauthn.verify_registration_response", return_value=_registered()):
            r = await client.post(
                "/api/v1/auth/passkeys/register/complete",
                json={
                    "challenge_key": options["challenge_key"],
                    "credential": {"id": _b64(b"cred-1"), "response": {}},
                    "device_name": "Laptop",
                },
                headers=headers,
            )
        assert r.status_code == 201

        options = (
            await client.post(
                "/api/v1/auth/passkeys/authenticate/begin", json={"email": "pk@test.com"}
            )
        ).json()
        assert [c["id"] for c in options["allowCredentials"]] == [_b64(b"cred-1")]
        with patch("webauthn.verify_authentication_response", return_value=_authenticated(1)):
            r = await client.post(
                "/api/v1/auth/passkeys/authenticate/complete",
                json={
                    "challenge_key": options["challenge_key"],
                    "credential": {"id": _b64(b"cred-1"), "response": {}},
                },
            )
        assert r.status_code == 200
        assert r.json()["access_token"]


@pytest.mark.asyncio
async def test_passkey_sign_in_failures_are_indistinguishable(passkey_app, adapter):
    """Unknown credential, bad signature, and inactive account all return the same
    401, so the endpoint cannot be used to probe credentials or account state."""
    failures = []
    transport = ASGITransport(app=passkey_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        async def attempt(credential_id: bytes, verify):
            options = (
                await client.post("/api/v1/auth/passkeys/authenticate/begin", json={})
            ).json()
            with patch("webauthn.verify_authentication_response", **verify):
                return await client.post(
                    "/api/v1/auth/passkeys/authenticate/complete",
                    json={
                        "challenge_key": options["challenge_key"],
                        "credential": {"id": _b64(credential_id), "response": {}},
                    },
                )

        user = await _user(adapter)
        await _register_passkey(adapter, user, InMemoryChallengeStore())

        failures.append(await attempt(b"never-registered", {"return_value": _authenticated(1)}))
        failures.append(await attempt(b"cred-1", {"side_effect": Exception("bad signature")}))
        await adapter.update_user(user.id, {"is_active": False})
        failures.append(await attempt(b"cred-1", {"return_value": _authenticated(2)}))

    assert [r.status_code for r in failures] == [401, 401, 401]
    assert len({r.text for r in failures}) == 1
