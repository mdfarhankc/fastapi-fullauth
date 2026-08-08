"""Shared adapter conformance suite.

Every adapter test module provides its own storage lifecycle fixtures plus an
``adapter`` fixture, then subclasses :class:`AdapterConformance` as
``class TestXxxAdapterConformance(AdapterConformance)`` so the whole adapter
contract runs against that backend. The class name deliberately does not start
with ``Test`` so pytest never collects the base itself.

Feature-dependent tests are gated on ``adapter.supports_feature(...)``;
adapters whose ``transaction()`` is best-effort (no atomicity) set
``atomic_transactions = False`` in their subclass.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.core.crypto import hash_password
from fastapi_fullauth.dependencies import current_user, require_permission, require_role
from fastapi_fullauth.exceptions import UserAlreadyExistsError
from fastapi_fullauth.types import (
    CreateUserSchema,
    OAuthAccount,
    PasskeyCredential,
    RefreshToken,
)

FAR_FUTURE = datetime.now(timezone.utc).replace(year=2999)


def _require_feature(adapter, feature):
    if not adapter.supports_feature(feature):
        pytest.skip(f"adapter does not support the '{feature}' feature")


class AdapterConformance:
    """Contract tests every adapter must pass. Subclass per adapter."""

    # Adapters whose transaction() is best-effort (yields self, no rollback)
    # set this to False; atomicity-dependent tests are skipped for them.
    atomic_transactions = True

    # --- Shared fixtures -------------------------------------------------

    @pytest.fixture
    def fullauth(self, adapter):
        return FullAuth(
            config=FullAuthConfig(
                SECRET_KEY="test-secret-key-that-is-long-enough-32b",
                PREVENT_REGISTRATION_ENUMERATION=False,
            ),
            adapter=adapter,
        )

    @pytest.fixture
    def app(self, fullauth):
        app = FastAPI()
        fullauth.init_app(app)

        @app.get("/me")
        async def me(user=Depends(current_user)):
            return user

        @app.get("/role-check")
        async def role_check(user=Depends(require_role("editor"))):
            return {"ok": True}

        @app.get("/perm-check")
        async def perm_check(user=Depends(require_permission("posts:edit"))):
            return {"ok": True}

        return app

    @pytest.fixture
    async def client(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.fixture
    def make_user(self, adapter):
        async def _make(email="user@test.com", password="pass123"):
            return await adapter.create_user(
                CreateUserSchema(email=email, password=password),
                hashed_password=hash_password(password),
            )

        return _make

    def _require_atomic(self):
        if not self.atomic_transactions:
            pytest.skip("adapter transaction() is best-effort (no atomicity)")

    # --- User CRUD -------------------------------------------------------

    async def test_create_and_get_user(self, adapter, make_user):
        user = await make_user("test@test.com")
        assert user.email == "test@test.com"
        assert user.is_active is True
        assert user.roles == []

        fetched = await adapter.get_user_by_id(user.id)
        assert fetched is not None
        assert fetched.email == "test@test.com"

    async def test_get_user_by_email(self, adapter, make_user):
        await make_user("find@test.com")

        user = await adapter.get_user_by_email("find@test.com")
        assert user is not None
        assert user.email == "find@test.com"

        assert await adapter.get_user_by_email("nope@test.com") is None

    async def test_create_user_duplicate_email_raises(self, make_user):
        await make_user("dup@test.com")
        with pytest.raises(UserAlreadyExistsError):
            await make_user("dup@test.com")

    async def test_email_is_normalized_on_create_and_lookup(self, adapter, make_user):
        created = await make_user("  Alice@Example.com  ")
        assert created.email == "alice@example.com"

        assert (await adapter.get_user_by_email("alice@example.com")) is not None
        assert (await adapter.get_user_by_email("ALICE@EXAMPLE.COM")) is not None
        assert (await adapter.get_user_by_email("  alice@example.com  ")) is not None

        with pytest.raises(UserAlreadyExistsError):
            await make_user("ALICE@example.com")

    async def test_get_user_by_field(self, adapter, make_user):
        await make_user("field@test.com")
        assert await adapter.get_user_by_field("email", "field@test.com") is not None

    async def test_get_user_by_field_unknown_raises(self, adapter):
        with pytest.raises(ValueError):
            await adapter.get_user_by_field("nonexistent", "x")

    async def test_update_user(self, adapter, make_user):
        user = await make_user("upd@test.com")
        updated = await adapter.update_user(user.id, {"display_name": "Updated Name"})
        assert updated.email == "upd@test.com"

    async def test_delete_user(self, adapter, make_user):
        user = await make_user("del@test.com")
        await adapter.delete_user(user.id)
        assert await adapter.get_user_by_id(user.id) is None

    async def test_password_operations(self, adapter, make_user):
        user = await make_user("pw@test.com")

        hashed = await adapter.get_hashed_password(user.id)
        assert hashed is not None

        await adapter.set_password(user.id, hash_password("newpass"))
        new_hashed = await adapter.get_hashed_password(user.id)
        assert new_hashed != hashed

    async def test_set_user_verified(self, adapter, make_user):
        user = await make_user("verify@test.com")
        assert user.is_verified is False

        await adapter.set_user_verified(user.id)
        user = await adapter.get_user_by_id(user.id)
        assert user.is_verified is True

    # --- Roles -----------------------------------------------------------

    async def test_assign_and_get_roles(self, adapter, make_user):
        _require_feature(adapter, "role")
        user = await make_user("role@test.com")

        await adapter.assign_role(user.id, "editor")
        await adapter.assign_role(user.id, "viewer")
        # re-assigning an existing role is idempotent
        await adapter.assign_role(user.id, "editor")

        roles = await adapter.get_user_roles(user.id)
        assert sorted(roles) == ["editor", "viewer"]

    async def test_remove_role(self, adapter, make_user):
        _require_feature(adapter, "role")
        user = await make_user("rmrole@test.com")

        await adapter.assign_role(user.id, "editor")
        await adapter.assign_role(user.id, "viewer")
        await adapter.remove_role(user.id, "editor")

        roles = await adapter.get_user_roles(user.id)
        assert roles == ["viewer"]

    # --- Refresh tokens --------------------------------------------------

    async def test_refresh_token_crud(self, adapter, make_user):
        user = await make_user("rt@test.com")

        token = RefreshToken(
            token="test-token-123",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc),
            family_id="family-1",
            revoked=False,
        )
        await adapter.store_refresh_token(token)

        stored = await adapter.get_refresh_token("test-token-123")
        assert stored is not None
        assert stored.family_id == "family-1"
        assert stored.revoked is False

        assert await adapter.revoke_refresh_token("test-token-123") is True
        stored = await adapter.get_refresh_token("test-token-123")
        assert stored.revoked is True

        # second revoke returns False = already revoked (the CAS signal)
        assert await adapter.revoke_refresh_token("test-token-123") is False
        # revoking an unknown token also returns False
        assert await adapter.revoke_refresh_token("does-not-exist") is False

    async def test_revoke_refresh_token_family(self, adapter, make_user):
        user = await make_user("rtf@test.com")
        for i in range(3):
            await adapter.store_refresh_token(
                RefreshToken(
                    token=f"family-token-{i}",
                    user_id=user.id,
                    expires_at=datetime.now(timezone.utc),
                    family_id="same-family",
                )
            )

        await adapter.revoke_refresh_token_family("same-family")
        for i in range(3):
            stored = await adapter.get_refresh_token(f"family-token-{i}")
            assert stored.revoked is True

    # --- Sessions --------------------------------------------------------

    async def test_list_and_revoke_sessions(self, adapter, make_user):
        _require_feature(adapter, "session")
        user = await make_user("sess@test.com")
        for fam in ("fam-a", "fam-b"):
            await adapter.store_refresh_token(
                RefreshToken(
                    token=f"tok-{fam}",
                    user_id=user.id,
                    expires_at=FAR_FUTURE,
                    family_id=fam,
                    user_agent="ua",
                    ip_address="1.2.3.4",
                )
            )

        sessions = await adapter.list_user_sessions(user.id)
        assert {s.family_id for s in sessions} == {"fam-a", "fam-b"}

        # revoke one session; not-owner family returns False
        assert await adapter.revoke_user_session(user.id, "fam-a") is True
        assert await adapter.revoke_user_session(user.id, "missing") is False
        sessions = await adapter.list_user_sessions(user.id)
        assert {s.family_id for s in sessions} == {"fam-b"}

    async def test_revoke_user_session_is_idempotent(self, adapter, make_user):
        _require_feature(adapter, "session")
        user = await make_user("sessidem@test.com")
        await adapter.store_refresh_token(
            RefreshToken(
                token="sess-tok",
                user_id=user.id,
                expires_at=datetime.now(timezone.utc),
                family_id="fam-x",
            )
        )

        assert await adapter.revoke_user_session(user.id, "fam-x") is True
        # re-revoking an already-revoked family is idempotent (must not 404)
        assert await adapter.revoke_user_session(user.id, "fam-x") is True
        # a family the user does not own returns False
        assert await adapter.revoke_user_session(user.id, "nope") is False

    async def test_revoke_sessions_except(self, adapter, make_user):
        _require_feature(adapter, "session")
        user = await make_user("sessx@test.com")
        for fam in ("keep", "drop-1", "drop-2"):
            await adapter.store_refresh_token(
                RefreshToken(
                    token=f"tok-{fam}", user_id=user.id, expires_at=FAR_FUTURE, family_id=fam
                )
            )

        revoked = await adapter.revoke_user_sessions_except(user.id, "keep")
        assert revoked == 2
        sessions = await adapter.list_user_sessions(user.id)
        assert {s.family_id for s in sessions} == {"keep"}

    # --- Permissions -----------------------------------------------------

    async def test_permission_crud(self, adapter):
        _require_feature(adapter, "permission")
        await adapter.assign_permission_to_role("editor", "posts:create")
        await adapter.assign_permission_to_role("editor", "posts:edit")

        perms = await adapter.get_role_permissions("editor")
        assert sorted(perms) == ["posts:create", "posts:edit"]

        await adapter.remove_permission_from_role("editor", "posts:create")
        perms = await adapter.get_role_permissions("editor")
        assert perms == ["posts:edit"]

    async def test_user_permissions_through_roles(self, adapter, make_user):
        _require_feature(adapter, "permission")
        user = await make_user("perms@test.com")

        await adapter.assign_role(user.id, "editor")
        await adapter.assign_role(user.id, "viewer")
        await adapter.assign_permission_to_role("editor", "posts:create")
        await adapter.assign_permission_to_role("editor", "posts:edit")
        await adapter.assign_permission_to_role("viewer", "posts:read")

        perms = await adapter.get_user_permissions(user.id)
        assert sorted(perms) == ["posts:create", "posts:edit", "posts:read"]

    # --- OAuth -----------------------------------------------------------

    async def test_oauth_account_duplicate_identity_is_idempotent(self, adapter, make_user):
        """Unique (provider, provider_user_id): a second insert for the same
        identity returns the existing row instead of erroring."""
        _require_feature(adapter, "oauth")
        u1 = await make_user("u1@test.com")
        u2 = await make_user("u2@test.com")

        first = await adapter.create_oauth_account(
            OAuthAccount(provider="github", provider_user_id="gh-1", user_id=u1.id)
        )
        second = await adapter.create_oauth_account(
            OAuthAccount(provider="github", provider_user_id="gh-1", user_id=u2.id)
        )
        assert second.user_id == first.user_id == u1.id

    async def test_oauth_account_crud(self, adapter, make_user):
        _require_feature(adapter, "oauth")
        user = await make_user("oauth@test.com")

        account = OAuthAccount(
            provider="google",
            provider_user_id="g-123",
            user_id=user.id,
            provider_email="oauth@test.com",
        )
        await adapter.create_oauth_account(account)

        fetched = await adapter.get_oauth_account("google", "g-123")
        assert fetched is not None
        assert fetched.provider_email == "oauth@test.com"

        accounts = await adapter.get_user_oauth_accounts(user.id)
        assert len(accounts) == 1

        updated = await adapter.update_oauth_account(
            "google", "g-123", {"access_token": "new-token"}
        )
        assert updated.access_token == "new-token"

        await adapter.delete_oauth_account("google", "g-123")
        assert await adapter.get_oauth_account("google", "g-123") is None

    # --- Passkeys --------------------------------------------------------

    async def test_passkey_crud_and_sign_count(self, adapter, make_user):
        _require_feature(adapter, "passkey")
        user = await make_user("pk@test.com")
        cred = PasskeyCredential(
            id=uuid4(),
            user_id=user.id,
            credential_id="cred-1",
            public_key="pub",
            sign_count=0,
            transports=["internal", "hybrid"],
        )
        await adapter.store_passkey(cred)

        fetched = await adapter.get_passkey_by_credential_id("cred-1")
        assert fetched is not None
        assert fetched.transports == ["internal", "hybrid"]
        assert len(await adapter.get_user_passkeys(user.id)) == 1

        # advancing the counter succeeds; a non-advancing value returns False
        assert await adapter.update_passkey_sign_count("cred-1", 5) is True
        assert await adapter.update_passkey_sign_count("cred-1", 3) is False

        await adapter.delete_passkey(cred.id)
        assert await adapter.get_passkey_by_credential_id("cred-1") is None

    # --- Transactions ----------------------------------------------------

    async def test_transaction_commits_all_steps(self, adapter, make_user):
        _require_feature(adapter, "role")
        async with adapter.transaction() as tx:
            user = await tx.create_user(
                CreateUserSchema(email="tx@test.com", password="pass123"),
                hashed_password=hash_password("pass123"),
            )
            await tx.assign_role(user.id, "editor")

        fetched = await adapter.get_user_by_email("tx@test.com")
        assert fetched is not None
        assert "editor" in fetched.roles

    async def test_transaction_rolls_back_on_error(self, adapter):
        self._require_atomic()

        class BoomError(Exception):
            pass

        with pytest.raises(BoomError):
            async with adapter.transaction() as tx:
                await tx.create_user(
                    CreateUserSchema(email="rollback@test.com", password="pass123"),
                    hashed_password=hash_password("pass123"),
                )
                raise BoomError

        assert await adapter.get_user_by_email("rollback@test.com") is None

    async def test_transaction_savepoint_isolates_duplicate(self, adapter, make_user):
        """A duplicate-user failure inside a transaction poisons only that
        statement; the surrounding transaction stays usable and still commits."""
        await make_user("exists@test.com")

        async with adapter.transaction() as tx:
            await tx.create_user(
                CreateUserSchema(email="before@test.com", password="pass123"),
                hashed_password=hash_password("pass123"),
            )
            with pytest.raises(UserAlreadyExistsError):
                await tx.create_user(
                    CreateUserSchema(email="exists@test.com", password="pass123"),
                    hashed_password=hash_password("pass123"),
                )
            await tx.create_user(
                CreateUserSchema(email="after@test.com", password="pass123"),
                hashed_password=hash_password("pass123"),
            )

        assert await adapter.get_user_by_email("before@test.com") is not None
        assert await adapter.get_user_by_email("after@test.com") is not None

    async def test_transaction_cannot_nest(self, adapter):
        self._require_atomic()
        async with adapter.transaction() as tx:
            with pytest.raises(RuntimeError):
                async with tx.transaction():
                    pass

    async def test_transaction_oauth_duplicate_returns_existing(self, adapter, make_user):
        _require_feature(adapter, "oauth")
        _require_feature(adapter, "role")
        user = await make_user("oauthtx@test.com")
        account = OAuthAccount(
            provider="github",
            provider_user_id="dup-1",
            user_id=user.id,
            provider_email="oauthtx@test.com",
        )
        await adapter.create_oauth_account(account)

        async with adapter.transaction() as tx:
            again = await tx.create_oauth_account(account)
            assert again.provider_user_id == "dup-1"
            await tx.assign_role(user.id, "editor")

        assert len(await adapter.get_user_oauth_accounts(user.id)) == 1
        fetched = await adapter.get_user_by_email("oauthtx@test.com")
        assert "editor" in fetched.roles

    # --- Full flow via HTTP ----------------------------------------------

    async def test_register_login_me_flow(self, client):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "flow@test.com", "password": "securepass123"},
        )
        assert r.status_code == 201

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "flow@test.com", "password": "securepass123"},
        )
        assert r.status_code == 200
        tokens = r.json()
        assert "access_token" in tokens
        assert tokens["refresh_token"]

        r = await client.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        assert r.status_code == 200
        assert r.json()["email"] == "flow@test.com"

    async def test_refresh_token_rotation(self, client):
        await client.post(
            "/api/v1/auth/register",
            json={"email": "rot@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "rot@test.com", "password": "securepass123"},
        )
        old_refresh = r.json()["refresh_token"]

        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert r.status_code == 200
        new_refresh = r.json()["refresh_token"]
        assert new_refresh != old_refresh

        # old token is rejected after rotation
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert r.status_code == 401

    async def test_role_and_permission_flow(self, client, adapter):
        _require_feature(adapter, "permission")
        await client.post(
            "/api/v1/auth/register",
            json={"email": "rbac@test.com", "password": "securepass123"},
        )
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "rbac@test.com", "password": "securepass123"},
        )
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
        user = await adapter.get_user_by_email("rbac@test.com")

        # no role: blocked
        assert (await client.get("/role-check", headers=headers)).status_code == 403

        # assign role: allowed
        await adapter.assign_role(user.id, "editor")
        assert (await client.get("/role-check", headers=headers)).status_code == 200

        # no permission: blocked
        assert (await client.get("/perm-check", headers=headers)).status_code == 403

        # assign permission: allowed
        await adapter.assign_permission_to_role("editor", "posts:edit")
        assert (await client.get("/perm-check", headers=headers)).status_code == 200
