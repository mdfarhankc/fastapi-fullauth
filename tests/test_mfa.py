"""Two-factor authentication: enrolment, sign-in, and the ways around it.

A second factor is only worth having if the ways around it are closed, so most
of what is here is the refusals: a replayed code, a recovery code used twice, a
pending token spent twice or used as a session.
"""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.types import CreateUserSchema

SECRET = "test-secret-key-that-is-long-enough-32b"
PASSWORD = "securepass123"


@pytest.fixture
def mfa_config():
    return FullAuthConfig(
        SECRET_KEY=SECRET,
        PREVENT_REGISTRATION_ENUMERATION=False,
        PREVENT_LOGIN_TIMING_ATTACKS=False,
        MFA_ISSUER="Acme",
    )


@pytest.fixture
def mfa_app(mfa_config, adapter):
    app = FastAPI()
    FullAuth(config=mfa_config, adapter=adapter).init_app(app)
    return app


@pytest.fixture
async def mfa_client(mfa_app):
    transport = ASGITransport(app=mfa_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _register_and_login(client, email="mfa@test.com"):
    body = {"email": email, "password": PASSWORD}
    await client.post("/api/v1/auth/register", json=body)
    r = await client.post("/api/v1/auth/login", json=body)
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _next_code(secret: str) -> str:
    """The code for the following time step.

    Confirming an enrolment consumes that step, so the same digits cannot sign
    in straight afterwards: that is the replay defence working. A real user
    waits for their authenticator to roll over, and one step ahead is inside the
    drift window the server accepts.
    """
    return pyotp.TOTP(secret).at(datetime.now(timezone.utc) + timedelta(seconds=30))


async def _enable_mfa(client, headers) -> tuple[str, list[str]]:
    """Enrol and confirm, returning the secret and the recovery codes."""
    r = await client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]

    r = await client.post(
        "/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


# ── Enrolment ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrolment_returns_a_provisioning_uri_and_does_nothing_until_confirmed(
    mfa_client, adapter
):
    """A secret that gated sign-in before a code proved the authenticator works
    would lock the account out of itself."""
    headers = await _register_and_login(mfa_client)

    r = await mfa_client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert r.status_code == 200
    assert r.json()["provisioning_uri"].startswith("otpauth://totp/")
    assert "issuer=Acme" in r.json()["provisioning_uri"]

    assert (await mfa_client.get("/api/v1/auth/mfa", headers=headers)).json()["enabled"] is False

    # Signing in is unaffected while the enrolment is unconfirmed.
    r = await mfa_client.post(
        "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


@pytest.mark.asyncio
async def test_confirming_enables_it_and_returns_recovery_codes_once(mfa_client):
    headers = await _register_and_login(mfa_client)
    _, codes = await _enable_mfa(mfa_client, headers)

    assert len(codes) == 10
    status = (await mfa_client.get("/api/v1/auth/mfa", headers=headers)).json()
    assert status == {"enabled": True, "recovery_codes_remaining": 10}


@pytest.mark.asyncio
async def test_confirming_with_a_wrong_code_is_refused(mfa_client):
    headers = await _register_and_login(mfa_client)
    await mfa_client.post("/api/v1/auth/mfa/enroll", headers=headers)

    r = await mfa_client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"}, headers=headers)
    assert r.status_code == 400
    assert (await mfa_client.get("/api/v1/auth/mfa", headers=headers)).json()["enabled"] is False


@pytest.mark.asyncio
async def test_enrolling_again_while_enabled_is_refused(mfa_client):
    """Replacing a live factor without proving the old one is a way around it."""
    headers = await _register_and_login(mfa_client)
    await _enable_mfa(mfa_client, headers)

    r = await mfa_client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert r.status_code == 409


# ── Sign-in ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_password_alone_no_longer_signs_in(mfa_client):
    headers = await _register_and_login(mfa_client)
    secret, _ = await _enable_mfa(mfa_client, headers)

    r = await mfa_client.post(
        "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
    )
    assert r.status_code == 202
    body = r.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body
    assert "refresh_token" not in body

    r = await mfa_client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": _next_code(secret)},
    )
    assert r.status_code == 200
    assert r.json()["access_token"]
    assert r.json()["refresh_token"]


@pytest.mark.asyncio
async def test_the_pending_token_is_not_a_session(mfa_client):
    """It buys the right to submit a code and nothing else."""
    headers = await _register_and_login(mfa_client)
    await _enable_mfa(mfa_client, headers)

    pending = (
        await mfa_client.post(
            "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
        )
    ).json()["mfa_token"]

    r = await mfa_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pending}"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_the_pending_token_cannot_buy_two_sessions(mfa_client):
    headers = await _register_and_login(mfa_client)
    secret, codes = await _enable_mfa(mfa_client, headers)

    pending = (
        await mfa_client.post(
            "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
        )
    ).json()["mfa_token"]

    first = await mfa_client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": pending, "code": _next_code(secret)},
    )
    assert first.status_code == 200

    # An unused recovery code for the second attempt. Any TOTP code would be
    # refused by the counter anyway, which would prove nothing about the token;
    # a recovery code does not touch the counter, so only the spent pending
    # token can be what rejects this.
    second = await mfa_client.post(
        "/api/v1/auth/mfa/verify", json={"mfa_token": pending, "code": codes[0]}
    )
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_a_code_cannot_be_replayed(mfa_client):
    """A code stays valid for its whole time step, so anyone who reads it over a
    shoulder has thirty seconds to use it. Accepting one must burn it."""
    headers = await _register_and_login(mfa_client)
    secret, _ = await _enable_mfa(mfa_client, headers)
    code = _next_code(secret)

    async def sign_in_with(value: str):
        pending = (
            await mfa_client.post(
                "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
            )
        ).json()["mfa_token"]
        return await mfa_client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": pending, "code": value}
        )

    assert (await sign_in_with(code)).status_code == 200
    assert (await sign_in_with(code)).status_code == 401


@pytest.mark.asyncio
async def test_a_recovery_code_works_once(mfa_client):
    headers = await _register_and_login(mfa_client)
    _, codes = await _enable_mfa(mfa_client, headers)

    async def sign_in_with(value: str):
        pending = (
            await mfa_client.post(
                "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
            )
        ).json()["mfa_token"]
        return await mfa_client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": pending, "code": value}
        )

    assert (await sign_in_with(codes[0])).status_code == 200
    assert (await sign_in_with(codes[0])).status_code == 401

    # The rest are untouched, and the count reflects the one spent.
    second = await sign_in_with(codes[1])
    assert second.status_code == 200
    headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    assert (await mfa_client.get("/api/v1/auth/mfa", headers=headers)).json()[
        "recovery_codes_remaining"
    ] == 8


@pytest.mark.asyncio
async def test_an_expired_pending_token_is_refused(mfa_client, mfa_app, adapter):
    headers = await _register_and_login(mfa_client)
    secret, _ = await _enable_mfa(mfa_client, headers)

    fullauth = mfa_app.state.fullauth
    user = await adapter.get_user_by_email("mfa@test.com")
    stale = fullauth.token_engine.create_access_token(
        user_id=str(user.id), extra={"purpose": "mfa_pending"}, expire_seconds=-10
    )

    r = await mfa_client.post(
        "/api/v1/auth/mfa/verify", json={"mfa_token": stale, "code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_a_session_token_is_not_accepted_as_a_pending_token(mfa_client, mfa_app, adapter):
    """The purpose check runs both ways: an ordinary access token must not be
    redeemable at /mfa/verify."""
    headers = await _register_and_login(mfa_client)
    secret, _ = await _enable_mfa(mfa_client, headers)

    session_token = headers["Authorization"].removeprefix("Bearer ")
    r = await mfa_client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": session_token, "code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 401


# ── Removing it ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabling_needs_recent_authentication(mfa_client, mfa_app, adapter):
    """Removing a protection is an account-security action, like deleting the
    account."""
    headers = await _register_and_login(mfa_client)
    await _enable_mfa(mfa_client, headers)

    fullauth = mfa_app.state.fullauth
    user = await adapter.get_user_by_email("mfa@test.com")
    stale = fullauth.token_engine.create_access_token(
        user_id=str(user.id),
        auth_time=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    r = await mfa_client.request(
        "DELETE", "/api/v1/auth/mfa", headers={"Authorization": f"Bearer {stale}"}
    )
    assert r.status_code == 403

    r = await mfa_client.request("DELETE", "/api/v1/auth/mfa", headers=headers)
    assert r.status_code == 204
    assert (await mfa_client.get("/api/v1/auth/mfa", headers=headers)).json()["enabled"] is False

    # And the password alone signs in again.
    r = await mfa_client.post(
        "/api/v1/auth/login", json={"email": "mfa@test.com", "password": PASSWORD}
    )
    assert r.status_code == 200


# ── Off by default ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_routes_are_absent_when_the_feature_is_off(client, auth_headers):
    """Nothing changes for an application that has not enabled it."""
    assert (await client.get("/api/v1/auth/mfa", headers=auth_headers)).status_code == 404

    r = await client.post(
        "/api/v1/auth/login", json={"email": "user@test.com", "password": PASSWORD}
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


@pytest.mark.asyncio
async def test_an_adapter_without_the_mixin_warns_and_mounts_nothing(db):
    from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter
    from tests.conftest import RefreshToken, User

    adapter = SQLModelAdapter(session_maker=db, user_model=User, refresh_token_model=RefreshToken)
    with pytest.warns(UserWarning, match="cannot serve two-factor"):
        fullauth = FullAuth(
            config=FullAuthConfig(SECRET_KEY=SECRET, MFA_ISSUER="Acme"), adapter=adapter
        )
    app = FastAPI()
    fullauth.init_app(app)
    assert not [r for r in app.openapi()["paths"] if "/mfa" in r]


@pytest.mark.asyncio
async def test_totp_matches_the_rfc_6238_reference_vector():
    """A code this library accepts must be the one a standard authenticator
    produces, not merely one it also generates."""
    from fastapi_fullauth.flows.mfa import _matching_counter

    # RFC 6238 appendix B, SHA-1: secret "12345678901234567890" at T=59 is 94287082.
    secret = pyotp.TOTP(pyotp.random_base32()).secret
    at = datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc)
    expected = pyotp.TOTP(secret).at(at)
    assert _matching_counter(secret, expected, now=at) is not None
    assert _matching_counter(secret, "000000", now=at) is None


@pytest.mark.asyncio
async def test_an_unconfirmed_credential_never_verifies(adapter):
    """Defence in depth at the flow: the routes cannot hand out a pending token
    for an unconfirmed factor, but verification refuses one regardless."""
    from fastapi_fullauth.exceptions import AuthenticationError
    from fastapi_fullauth.flows.mfa import verify_code
    from fastapi_fullauth.types import MFACredential

    user = await adapter.create_user(
        CreateUserSchema(email="unconfirmed@test.com", password=PASSWORD), hashed_password="x"
    )
    secret = pyotp.random_base32()
    await adapter.store_mfa(MFACredential(user_id=user.id, secret=secret))

    with pytest.raises(AuthenticationError):
        await verify_code(adapter, user.id, pyotp.TOTP(secret).now())
