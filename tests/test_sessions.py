"""Tests for session management: device/IP capture, the access-token family
claim, and the sessions router (list, revoke one, revoke others)."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth

SESSIONS = "/api/v1/auth/sessions"


async def _login(client, *, user_agent="pytest-agent", email="user@test.com"):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "securepass123"},
        headers={"User-Agent": user_agent},
    )
    assert r.status_code == 200
    return r.json()


def _bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.mark.asyncio
async def test_access_token_carries_family_id(client, fullauth, registered_user):
    tokens = await _login(client)
    payload = await fullauth.token_engine.decode_token(tokens["access_token"])
    stored = await fullauth.adapter.get_refresh_token(tokens["refresh_token"])
    assert payload.family_id is not None
    assert payload.family_id == stored.family_id


@pytest.mark.asyncio
async def test_login_records_device_and_ip(client, fullauth, registered_user):
    tokens = await _login(client, user_agent="my-browser/1.0")
    stored = await fullauth.adapter.get_refresh_token(tokens["refresh_token"])
    assert stored.user_agent == "my-browser/1.0"
    assert isinstance(stored.ip_address, str)


@pytest.mark.asyncio
async def test_list_sessions_flags_current(client, registered_user):
    tokens = await _login(client)
    r = await client.get(SESSIONS, headers=_bearer(tokens))
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) == 1
    assert sessions[0]["current"] is True
    assert sessions[0]["user_agent"] == "pytest-agent"


@pytest.mark.asyncio
async def test_multiple_sessions_one_current(client, registered_user):
    first = await _login(client, user_agent="device-A")
    await _login(client, user_agent="device-B")

    r = await client.get(SESSIONS, headers=_bearer(first))
    sessions = r.json()
    assert len(sessions) == 2
    current = [s for s in sessions if s["current"]]
    assert len(current) == 1
    assert current[0]["user_agent"] == "device-A"


@pytest.mark.asyncio
async def test_revoke_one_session(client, fullauth, registered_user):
    keep = await _login(client, user_agent="keep")
    drop = await _login(client, user_agent="drop")
    drop_family = (await fullauth.adapter.get_refresh_token(drop["refresh_token"])).family_id

    r = await client.delete(f"{SESSIONS}/{drop_family}", headers=_bearer(keep))
    assert r.status_code == 204

    # the revoked session's refresh token can no longer rotate
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": drop["refresh_token"]})
    assert r.status_code == 401

    # and it disappears from the list, leaving only the kept session
    r = await client.get(SESSIONS, headers=_bearer(keep))
    families = [s["family_id"] for s in r.json()]
    assert drop_family not in families
    assert len(families) == 1


@pytest.mark.asyncio
async def test_revoke_unknown_session_404(client, registered_user):
    tokens = await _login(client)
    r = await client.delete(f"{SESSIONS}/does-not-exist", headers=_bearer(tokens))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_cannot_revoke_another_users_session(client, fullauth, registered_user):
    victim = await _login(client)
    victim_family = (await fullauth.adapter.get_refresh_token(victim["refresh_token"])).family_id

    await client.post(
        "/api/v1/auth/register",
        json={"email": "attacker@test.com", "password": "securepass123"},
    )
    attacker = await _login(client, email="attacker@test.com")

    r = await client.delete(f"{SESSIONS}/{victim_family}", headers=_bearer(attacker))
    assert r.status_code == 404

    # the victim's session is untouched
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": victim["refresh_token"]})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_revoke_other_sessions(client, registered_user):
    current = await _login(client, user_agent="current")
    other_a = await _login(client, user_agent="other-a")
    other_b = await _login(client, user_agent="other-b")

    r = await client.post(f"{SESSIONS}/revoke-others", headers=_bearer(current))
    assert r.status_code == 200
    assert "2" in r.json()["detail"]

    # both other sessions are dead
    for other in (other_a, other_b):
        rr = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": other["refresh_token"]}
        )
        assert rr.status_code == 401

    # only the current session survives
    r = await client.get(SESSIONS, headers=_bearer(current))
    assert len(r.json()) == 1
    assert r.json()[0]["current"] is True


@pytest.mark.asyncio
async def test_sessions_require_auth(client):
    r = await client.get(SESSIONS)
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_sessions_router_excluded_by_allowlist(config, adapter):
    fullauth = FullAuth(config=config, adapter=adapter)
    app = FastAPI()
    fullauth.init_app(app, include_routers=["auth"])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        await c.post(
            "/api/v1/auth/register",
            json={"email": "u@test.com", "password": "securepass123"},
        )
        tokens = await _login(c, email="u@test.com")
        r = await c.get(SESSIONS, headers=_bearer(tokens))
        assert r.status_code == 404
