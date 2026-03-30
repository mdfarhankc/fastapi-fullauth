from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from fastapi_fullauth.dependencies.current_user import _extract_token, _get_fullauth
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
from fastapi_fullauth.types import CreateUserSchema, TokenPair, UserSchema

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


async def _get_custom_claims(fullauth: FullAuth, user: UserSchema) -> dict:
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


WEAK_PASSWORD_EXCEPTION = lambda errors: Response(  # noqa: E731
    status_code=422,
    content='{"detail": "' + str(errors) + '"}',
    media_type="application/json",
)


def create_auth_router(
    create_user_schema: type[CreateUserSchema] = CreateUserSchema,
) -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.post("/register", status_code=201)
    async def register_route(
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        if not fullauth.is_route_enabled("register"):
            return Response(status_code=404)

        body = await request.json()
        try:
            data = fullauth.create_user_schema(**body)
        except Exception as e:
            from fastapi import HTTPException

            raise HTTPException(status_code=422, detail=str(e))

        # validate password strength
        try:
            fullauth.password_validator.validate(data.password)
        except InvalidPasswordError as e:
            from fastapi import HTTPException

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
        fullauth: FullAuth = Depends(_get_fullauth),
        form_data: OAuth2PasswordRequestForm = Depends(),
    ):
        if not fullauth.is_route_enabled("login"):
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
        fullauth: FullAuth = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ):
        if not fullauth.is_route_enabled("logout"):
            return Response(status_code=404)

        try:
            payload = fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        await logout(fullauth.token_engine, payload)
        await fullauth.hooks.emit("after_logout", user_id=payload.sub)

        response = Response(status_code=204)
        for backend in fullauth.backends:
            await backend.delete_token(response)
        return response

    @router.post("/refresh", response_model=TokenPair)
    async def refresh_route(
        data: RefreshRequest,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        if not fullauth.is_route_enabled("refresh"):
            return Response(status_code=404)

        try:
            payload = fullauth.token_engine.decode_token(data.refresh_token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if payload.type != "refresh":
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(payload.sub)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        # blacklist old refresh token
        fullauth.token_engine.blacklist_token(payload.jti)

        roles = await fullauth.adapter.get_user_roles(str(user.id))
        extra_claims = await _get_custom_claims(fullauth, user)
        access, refresh = fullauth.token_engine.create_token_pair(
            user_id=str(user.id), roles=roles, extra=extra_claims
        )
        return TokenPair(access_token=access, refresh_token=refresh)

    @router.post("/verify-email/request", status_code=202)
    async def verify_email_request_route(
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ):
        if not fullauth.is_route_enabled("verify-email"):
            return Response(status_code=404)

        try:
            payload = fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        verify_token = await create_email_verification_token(
            fullauth.adapter, fullauth.token_engine, payload.sub
        )
        if verify_token and fullauth.on_send_verification_email:
            user = await fullauth.adapter.get_user_by_id(payload.sub)
            if user:
                await fullauth.on_send_verification_email(user.email, verify_token)

        return {"detail": "If eligible, a verification email has been sent."}

    @router.post("/verify-email/confirm", status_code=200)
    async def verify_email_confirm_route(
        data: VerifyEmailRequest,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        if not fullauth.is_route_enabled("verify-email"):
            return Response(status_code=404)

        try:
            user = await verify_email(fullauth.adapter, fullauth.token_engine, data.token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if user:
            await fullauth.hooks.emit("after_email_verify", user=user)

        return {"detail": "Email verified."}

    @router.post("/password-reset/request", status_code=202)
    async def password_reset_request_route(
        data: PasswordResetRequest,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        if not fullauth.is_route_enabled("password-reset"):
            return Response(status_code=404)

        token = await request_password_reset(
            fullauth.adapter, fullauth.token_engine, data.email
        )

        # send email if callback is set and token was generated
        if token and fullauth.on_send_password_reset_email:
            await fullauth.on_send_password_reset_email(data.email, token)

        # always return 202 to prevent email enumeration
        return {"detail": "If the email exists, a reset link has been sent."}

    @router.post("/password-reset/confirm", status_code=200)
    async def password_reset_confirm_route(
        data: PasswordResetConfirm,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        if not fullauth.is_route_enabled("password-reset"):
            return Response(status_code=404)

        # validate new password strength
        try:
            fullauth.password_validator.validate(data.new_password)
        except InvalidPasswordError as e:
            from fastapi import HTTPException

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

        return {"detail": "Password has been reset."}

    return router
