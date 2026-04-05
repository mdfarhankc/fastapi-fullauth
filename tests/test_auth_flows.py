import pytest


@pytest.mark.asyncio
async def test_register(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "new@test.com", "password": "securepass123"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == "new@test.com"
    assert data["is_active"] is True
    assert data["is_verified"] is False


@pytest.mark.asyncio
async def test_register_duplicate(client, registered_user):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@test.com", "password": "short"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client, registered_user):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "wrongpassword"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@test.com", "password": "whatever123"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_authenticated(client, auth_headers):
    r = await client.get("/me", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["email"] == "user@test.com"


@pytest.mark.asyncio
async def test_me_no_token(client):
    r = await client.get("/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_invalid_token(client):
    r = await client.get("/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout(client, auth_headers, login_tokens):
    r = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert r.status_code == 204

    # token should be blacklisted now
    r = await client.get("/me", headers=auth_headers)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh(client, login_tokens):
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["access_token"] != login_tokens["access_token"]


@pytest.mark.asyncio
async def test_refresh_reuse_blocked(client, login_tokens):
    # first refresh works
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 200

    # second use of same refresh token should fail (blacklisted)
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["refresh_token"]},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_access_token_fails(client, login_tokens):
    r = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_tokens["access_token"]},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_flow(client, registered_user, fullauth):
    # request reset
    r = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "user@test.com"},
    )
    assert r.status_code == 202

    # generate token manually for testing (normally sent via email)
    from fastapi_fullauth.flows.password_reset import request_password_reset

    token = await request_password_reset(fullauth.adapter, fullauth.token_engine, "user@test.com")
    assert token is not None

    # confirm reset
    r = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "newpassword123"},
    )
    assert r.status_code == 200

    # login with new password
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "newpassword123"},
    )
    assert r.status_code == 200

    # old password should fail
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@test.com", "password": "securepass123"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_nonexistent_user(client):
    r = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "nobody@test.com"},
    )
    # should still return 202 to prevent enumeration
    assert r.status_code == 202
