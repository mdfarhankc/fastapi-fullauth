from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from fastapi_fullauth.core.crypto import hash_password, verify_password
from fastapi_fullauth.dependencies.current_user import (
    CurrentUser,
    SuperUser,
    VerifiedUser,
    _extract_token,
    _get_fullauth,
)
from fastapi_fullauth.exceptions import (
    ACCOUNT_LOCKED_EXCEPTION,
    CREDENTIALS_EXCEPTION,
    USER_EXISTS_EXCEPTION,
    AccountLockedError,
    AuthenticationError,
    InvalidPasswordError,
    TokenError,
    UserAlreadyExistsError,
)
from fastapi_fullauth.flows.email_verify import create_email_verification_token, verify_email
from fastapi_fullauth.flows.login import login
from fastapi_fullauth.flows.logout import logout
from fastapi_fullauth.flows.password_reset import request_password_reset, reset_password
from fastapi_fullauth.flows.register import register
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, TokenPair, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def _build_login_model(login_field: str) -> type[BaseModel]:
    from pydantic import create_model

    return create_model("LoginRequest", **{login_field: (str, ...), "password": (str, ...)})


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class VerifyEmailRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class RoleAssignment(BaseModel):
    user_id: str
    role: str


class MessageResponse(BaseModel):
    detail: str


def create_auth_router(
    create_user_schema: type[CreateUserSchema] = CreateUserSchema,
    user_schema: type[UserSchema] = UserSchema,
    login_field: str = "email",
    enabled_routes: set[str] | None = None,
) -> APIRouter:
    LoginRequest = _build_login_model(login_field)  # noqa: N806
    router = APIRouter()

    def _on(route: str) -> bool:
        return enabled_routes is None or route in enabled_routes

    # ── auth flow ────────────────────────────────────────────────────

    if _on("register"):

        @router.post(
            "/register",
            status_code=201,
            response_model=user_schema,
            description="Create a new user account.",
        )
        async def register_route(
            request: Request,
            fullauth: "FullAuth" = Depends(_get_fullauth),
            data: create_user_schema = Body(...),  # type: ignore[valid-type]
        ) -> UserSchema:
            client_ip = request.client.host if request.client else "unknown"
            await fullauth.check_auth_rate_limit("register", client_ip)

            try:
                fullauth.password_validator.validate(data.password)
            except InvalidPasswordError as e:
                raise HTTPException(status_code=422, detail=str(e))

            try:
                user = await register(fullauth.adapter, data, login_field=login_field)
            except UserAlreadyExistsError:
                raise USER_EXISTS_EXCEPTION

            await fullauth.hooks.emit("after_register", user=user)
            return user

    if _on("login"):

        @router.post(
            "/login",
            status_code=200,
            description="Authenticate and get access + refresh tokens.",
        )
        async def login_route(
            data: LoginRequest,  # type: ignore[valid-type]
            request: Request,
            response: Response,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ):
            client_ip = request.client.host if request.client else "unknown"
            await fullauth.check_auth_rate_limit("login", client_ip)

            identifier = getattr(data, login_field)
            user = await fullauth.adapter.get_user_by_field(login_field, identifier)
            extra_claims = await fullauth.get_custom_claims(user) if user else {}

            try:
                tokens = await login(
                    adapter=fullauth.adapter,
                    token_engine=fullauth.token_engine,
                    identifier=identifier,
                    password=data.password,
                    login_field=login_field,
                    lockout=fullauth.lockout,
                    extra_claims=extra_claims,
                    user=user,
                )
            except AccountLockedError:
                raise ACCOUNT_LOCKED_EXCEPTION
            except AuthenticationError:
                raise CREDENTIALS_EXCEPTION

            for backend in fullauth.backends:
                await backend.write_token(response, tokens.access_token)

            await fullauth.hooks.emit("after_login", user=user)

            if fullauth.include_user_in_login and user:
                return {
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "token_type": tokens.token_type,
                    "expires_in": tokens.expires_in,
                    "user": user.model_dump(),
                }

            return tokens

    if _on("refresh"):

        @router.post(
            "/refresh",
            status_code=200,
            response_model=TokenPair,
            description="Rotate token pair. Reuse of old tokens revokes the session.",
        )
        async def refresh_route(
            data: RefreshRequest,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> TokenPair:
            try:
                payload = await fullauth.token_engine.decode_token(data.refresh_token)
            except TokenError:
                raise CREDENTIALS_EXCEPTION

            if payload.type != "refresh":
                raise CREDENTIALS_EXCEPTION

            user = await fullauth.adapter.get_user_by_id(payload.sub)
            if user is None or not user.is_active:
                raise CREDENTIALS_EXCEPTION

            # reuse detection: if this token was already rotated, someone stole it
            stored = await fullauth.adapter.get_refresh_token(data.refresh_token)
            if stored is not None and stored.revoked:
                await fullauth.adapter.revoke_refresh_token_family(stored.family_id)
                raise CREDENTIALS_EXCEPTION

            roles = await fullauth.adapter.get_user_roles(str(user.id))
            extra_claims = await fullauth.get_custom_claims(user)

            if fullauth.config.REFRESH_TOKEN_ROTATION:
                await fullauth.token_engine.blacklist_token(
                    payload.jti,
                    ttl_seconds=fullauth.config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
                )
                if stored is not None:
                    await fullauth.adapter.revoke_refresh_token(data.refresh_token)

                access, refresh_meta = fullauth.token_engine.create_token_pair(
                    user_id=str(user.id),
                    roles=roles,
                    extra=extra_claims,
                    family_id=payload.family_id,
                )

                await fullauth.adapter.store_refresh_token(
                    RefreshToken(
                        token=refresh_meta.token,
                        user_id=str(user.id),
                        expires_at=refresh_meta.expires_at,
                        family_id=refresh_meta.family_id,
                    )
                )
                refresh_token = refresh_meta.token
            else:
                access = fullauth.token_engine.create_access_token(
                    user_id=str(user.id),
                    roles=roles,
                    extra=extra_claims,
                )
                refresh_token = data.refresh_token

            return TokenPair(
                access_token=access,
                refresh_token=refresh_token,
                expires_in=fullauth.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )

    if _on("logout"):

        @router.post(
            "/logout",
            status_code=204,
            description="Blacklist token. Pass refresh_token in body to revoke the session.",
        )
        async def logout_route(
            fullauth: "FullAuth" = Depends(_get_fullauth),
            token: str = Depends(_extract_token),
            data: LogoutRequest | None = Body(None),
        ) -> None:
            try:
                payload = await fullauth.token_engine.decode_token(token)
            except TokenError:
                raise CREDENTIALS_EXCEPTION

            await logout(
                fullauth.token_engine,
                payload,
                adapter=fullauth.adapter,
                refresh_token=data.refresh_token if data else None,
            )
            await fullauth.hooks.emit("after_logout", user_id=payload.sub)

            response = Response(status_code=204)
            for backend in fullauth.backends:
                await backend.delete_token(response)
            return response

    # ── current user ─────────────────────────────────────────────────

    if _on("me"):

        @router.get(
            "/me",
            status_code=200,
            response_model=user_schema,
            description="Get the currently authenticated user.",
        )
        async def me_route(
            user: CurrentUser,
        ) -> UserSchema:
            return user

    if _on("verified-me"):

        @router.get(
            "/me/verified",
            status_code=200,
            response_model=user_schema,
            description="Get the current user. Requires verified email.",
        )
        async def verified_me_route(
            user: VerifiedUser,
        ) -> UserSchema:
            return user

    if _on("update-profile"):

        @router.patch(
            "/me",
            status_code=200,
            response_model=user_schema,
            description="Update profile fields. Protected fields are filtered out.",
        )
        async def update_me_route(
            user: CurrentUser,
            fullauth: "FullAuth" = Depends(_get_fullauth),
            data: dict = Body(...),
        ) -> UserSchema:
            # don't let users escalate their own privileges
            protected = {
                "id",
                "email",
                "hashed_password",
                "is_active",
                "is_verified",
                "is_superuser",
                "roles",
                "password",
                "created_at",
                "refresh_tokens",
            }
            updates = {k: v for k, v in data.items() if k not in protected}
            if not updates:
                raise HTTPException(status_code=400, detail="No valid fields to update")

            return await fullauth.adapter.update_user(str(user.id), updates)

    if _on("delete-account"):

        @router.delete("/me", status_code=204, description="Delete your own account.")
        async def delete_me_route(
            user: CurrentUser,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> None:
            await fullauth.adapter.revoke_all_user_refresh_tokens(str(user.id))
            await fullauth.adapter.delete_user(str(user.id))
            return Response(status_code=204)

    if _on("change-password"):

        @router.post(
            "/change-password",
            status_code=200,
            response_model=MessageResponse,
            description="Change password. Requires current password.",
        )
        async def change_password_route(
            data: ChangePasswordRequest,
            user: CurrentUser,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> MessageResponse:
            hashed = await fullauth.adapter.get_hashed_password(str(user.id))
            if hashed is None or not verify_password(data.current_password, hashed):
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            try:
                fullauth.password_validator.validate(data.new_password)
            except InvalidPasswordError as e:
                raise HTTPException(status_code=422, detail=str(e))

            await fullauth.adapter.set_password(str(user.id), hash_password(data.new_password))
            await fullauth.adapter.revoke_all_user_refresh_tokens(str(user.id))
            await fullauth.hooks.emit("after_password_change", user=user)
            return MessageResponse(detail="Password changed successfully.")

    # ── email & password reset ───────────────────────────────────────

    if _on("verify-email"):

        @router.post(
            "/verify-email/request",
            status_code=202,
            response_model=MessageResponse,
            description="Send a verification email to the current user.",
        )
        async def verify_email_request_route(
            user: CurrentUser,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> MessageResponse:
            verify_token = await create_email_verification_token(
                fullauth.adapter, fullauth.token_engine, str(user.id)
            )
            if verify_token:
                await fullauth.hooks.emit(
                    "send_verification_email", email=user.email, token=verify_token
                )

            return MessageResponse(detail="If eligible, a verification email has been sent.")

        @router.post(
            "/verify-email/confirm",
            status_code=200,
            response_model=MessageResponse,
            description="Confirm email verification with the token.",
        )
        async def verify_email_confirm_route(
            data: VerifyEmailRequest,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> MessageResponse:
            try:
                user = await verify_email(fullauth.adapter, fullauth.token_engine, data.token)
            except TokenError:
                raise CREDENTIALS_EXCEPTION

            if user:
                await fullauth.hooks.emit("after_email_verify", user=user)

            return MessageResponse(detail="Email verified.")

    if _on("password-reset"):

        @router.post(
            "/password-reset/request",
            status_code=202,
            response_model=MessageResponse,
            description="Request a password reset email.",
        )
        async def password_reset_request_route(
            data: PasswordResetRequest,
            request: Request,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> MessageResponse:
            client_ip = request.client.host if request.client else "unknown"
            await fullauth.check_auth_rate_limit("password-reset", client_ip)

            token = await request_password_reset(
                fullauth.adapter, fullauth.token_engine, data.email
            )

            if token:
                await fullauth.hooks.emit(
                    "send_password_reset_email", email=data.email, token=token
                )

            return MessageResponse(detail="If the email exists, a reset link has been sent.")

        @router.post(
            "/password-reset/confirm",
            status_code=200,
            response_model=MessageResponse,
            description="Set a new password using the reset token.",
        )
        async def password_reset_confirm_route(
            data: PasswordResetConfirm,
            fullauth: "FullAuth" = Depends(_get_fullauth),
        ) -> MessageResponse:
            try:
                fullauth.password_validator.validate(data.new_password)
            except InvalidPasswordError as e:
                raise HTTPException(status_code=422, detail=str(e))

            try:
                user = await reset_password(
                    fullauth.adapter,
                    fullauth.token_engine,
                    data.token,
                    data.new_password,
                )
            except TokenError:
                raise CREDENTIALS_EXCEPTION

            if user:
                await fullauth.hooks.emit("after_password_reset", user=user)

            return MessageResponse(detail="Password has been reset.")

    # ── admin ────────────────────────────────────────────────────────

    @router.post(
        "/admin/assign-role",
        status_code=200,
        response_model=MessageResponse,
        description="Assign a role to a user. Superuser only.",
    )
    async def assign_role_route(
        data: RoleAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        target = await fullauth.adapter.get_user_by_id(data.user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        await fullauth.adapter.assign_role(data.user_id, data.role)
        return MessageResponse(detail=f"Role '{data.role}' assigned to user {data.user_id}.")

    @router.post(
        "/admin/remove-role",
        status_code=200,
        response_model=MessageResponse,
        description="Remove a role from a user. Superuser only.",
    )
    async def remove_role_route(
        data: RoleAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        await fullauth.adapter.remove_role(data.user_id, data.role)
        return MessageResponse(detail=f"Role '{data.role}' removed from user {data.user_id}.")

    return router
