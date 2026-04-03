from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from fastapi_fullauth.dependencies.current_user import (
    _extract_token,
    _get_fullauth,
    current_user,
)
from fastapi_fullauth.exceptions import (
    ACCOUNT_LOCKED_EXCEPTION,
    CREDENTIALS_EXCEPTION,
    FORBIDDEN_EXCEPTION,
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
from fastapi_fullauth.types import CreateUserSchema, RefreshToken, Route, TokenPair, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


async def _get_custom_claims(fullauth: "FullAuth", user: UserSchema) -> dict:
    """Build custom token claims if a callback is configured."""
    if fullauth.on_create_token_claims:
        return await fullauth.on_create_token_claims(user)
    return {}


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


class RoleAssignment(BaseModel):
    user_id: str
    role: str


class MessageResponse(BaseModel):
    detail: str


WEAK_PASSWORD_EXCEPTION = lambda errors: Response(  # noqa: E731
    status_code=422,
    content='{"detail": "' + str(errors) + '"}',
    media_type="application/json",
)


def create_auth_router(
    create_user_schema: type[CreateUserSchema] = CreateUserSchema,
) -> APIRouter:
    router = APIRouter()

    @router.get("/me")
    async def me_route(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        user: UserSchema = Depends(current_user),
    ):
        if not fullauth.is_route_enabled(Route.ME):
            return Response(status_code=404)
        return user

    @router.post("/register", status_code=201)
    async def register_route(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        data: create_user_schema = Body(...),  # type: ignore[valid-type]
    ):
        if not fullauth.is_route_enabled(Route.REGISTER):
            return Response(status_code=404)

        # validate password strength
        try:
            fullauth.password_validator.validate(data.password)
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        try:
            user = await register(fullauth.adapter, data)
        except UserAlreadyExistsError:
            raise USER_EXISTS_EXCEPTION

        await fullauth.hooks.emit("after_register", user=user)
        return user

    @router.post("/login")
    async def login_route(
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        form_data: OAuth2PasswordRequestForm = Depends(),
    ):
        if not fullauth.is_route_enabled(Route.LOGIN):
            return Response(status_code=404)

        # build custom claims before login so they get embedded in the token
        user = await fullauth.adapter.get_user_by_email(form_data.username)
        extra_claims = await _get_custom_claims(fullauth, user) if user else {}

        try:
            tokens = await login(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                email=form_data.username,
                password=form_data.password,
                lockout=fullauth.lockout,
                extra_claims=extra_claims,
            )
        except AccountLockedError:
            raise ACCOUNT_LOCKED_EXCEPTION
        except AuthenticationError:
            raise CREDENTIALS_EXCEPTION

        # write token to cookie if cookie backend is active
        for backend in fullauth.backends:
            await backend.write_token(response, tokens.access_token)

        await fullauth.hooks.emit("after_login", user=user)

        if fullauth.include_user_in_login and user:
            return {
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "token_type": tokens.token_type,
                "user": user.model_dump(),
            }

        return tokens

    @router.post("/logout", status_code=204)
    async def logout_route(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
        data: LogoutRequest | None = Body(None),
    ):
        if not fullauth.is_route_enabled(Route.LOGOUT):
            return Response(status_code=404)

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

    @router.post("/refresh", response_model=TokenPair)
    async def refresh_route(
        data: RefreshRequest,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> TokenPair:
        if not fullauth.is_route_enabled(Route.REFRESH):
            return Response(status_code=404)

        try:
            payload = await fullauth.token_engine.decode_token(data.refresh_token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if payload.type != "refresh":
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(payload.sub)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        # check DB for revocation / reuse detection
        stored = await fullauth.adapter.get_refresh_token(data.refresh_token)
        if stored is not None and stored.revoked:
            # token was already used — possible theft, revoke entire family
            await fullauth.adapter.revoke_refresh_token_family(stored.family_id)
            raise CREDENTIALS_EXCEPTION

        if fullauth.config.REFRESH_TOKEN_ROTATION:
            # revoke old token
            await fullauth.token_engine.blacklist_token(
                payload.jti,
                ttl_seconds=fullauth.config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            )
            if stored is not None:
                await fullauth.adapter.revoke_refresh_token(data.refresh_token)

            # issue new pair in the same family
            roles = await fullauth.adapter.get_user_roles(str(user.id))
            extra_claims = await _get_custom_claims(fullauth, user)
            access, refresh = fullauth.token_engine.create_token_pair(
                user_id=str(user.id), roles=roles, extra=extra_claims,
                family_id=payload.family_id,
            )

            # persist new refresh token
            new_payload = await fullauth.token_engine.decode_token(refresh)
            await fullauth.adapter.store_refresh_token(RefreshToken(
                token=refresh,
                user_id=str(user.id),
                expires_at=new_payload.exp,
                family_id=payload.family_id,
            ))
        else:
            # no rotation — only issue a new access token
            roles = await fullauth.adapter.get_user_roles(str(user.id))
            extra_claims = await _get_custom_claims(fullauth, user)
            access = fullauth.token_engine.create_access_token(
                user_id=str(user.id), roles=roles, extra=extra_claims,
            )
            refresh = data.refresh_token

        return TokenPair(access_token=access, refresh_token=refresh)

    @router.post("/verify-email/request", status_code=202, response_model=MessageResponse)
    async def verify_email_request_route(
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> MessageResponse:
        if not fullauth.is_route_enabled(Route.VERIFY_EMAIL):
            return Response(status_code=404)

        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        verify_token = await create_email_verification_token(
            fullauth.adapter, fullauth.token_engine, payload.sub
        )
        if verify_token:
            user = await fullauth.adapter.get_user_by_id(payload.sub)
            if user:
                await fullauth.hooks.emit(
                    "send_verification_email", email=user.email, token=verify_token
                )

        return MessageResponse(detail="If eligible, a verification email has been sent.")

    @router.post("/verify-email/confirm", status_code=200, response_model=MessageResponse)
    async def verify_email_confirm_route(
        data: VerifyEmailRequest,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        if not fullauth.is_route_enabled(Route.VERIFY_EMAIL):
            return Response(status_code=404)

        try:
            user = await verify_email(fullauth.adapter, fullauth.token_engine, data.token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if user:
            await fullauth.hooks.emit("after_email_verify", user=user)

        return MessageResponse(detail="Email verified.")

    @router.post("/password-reset/request", status_code=202, response_model=MessageResponse)
    async def password_reset_request_route(
        data: PasswordResetRequest,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        if not fullauth.is_route_enabled(Route.PASSWORD_RESET):
            return Response(status_code=404)

        token = await request_password_reset(
            fullauth.adapter, fullauth.token_engine, data.email
        )

        if token:
            await fullauth.hooks.emit(
                "send_password_reset_email", email=data.email, token=token
            )

        # always return 202 to prevent email enumeration
        return MessageResponse(detail="If the email exists, a reset link has been sent.")

    @router.post("/password-reset/confirm", status_code=200, response_model=MessageResponse)
    async def password_reset_confirm_route(
        data: PasswordResetConfirm,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        if not fullauth.is_route_enabled(Route.PASSWORD_RESET):
            return Response(status_code=404)

        # validate new password strength
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

    # --- Admin: Role management (superuser only) ---

    @router.post("/admin/assign-role", response_model=MessageResponse)
    async def assign_role_route(
        data: RoleAssignment,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> MessageResponse:
        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        caller = await fullauth.adapter.get_user_by_id(payload.sub)
        if caller is None or not caller.is_superuser:
            raise FORBIDDEN_EXCEPTION

        target = await fullauth.adapter.get_user_by_id(data.user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        await fullauth.adapter.assign_role(data.user_id, data.role)
        return MessageResponse(detail=f"Role '{data.role}' assigned to user {data.user_id}.")

    @router.post("/admin/remove-role", response_model=MessageResponse)
    async def remove_role_route(
        data: RoleAssignment,
        request: Request,
        fullauth: "FullAuth" = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ) -> MessageResponse:
        try:
            payload = await fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        caller = await fullauth.adapter.get_user_by_id(payload.sub)
        if caller is None or not caller.is_superuser:
            raise FORBIDDEN_EXCEPTION

        await fullauth.adapter.remove_role(data.user_id, data.role)
        return MessageResponse(detail=f"Role '{data.role}' removed from user {data.user_id}.")

    return router
