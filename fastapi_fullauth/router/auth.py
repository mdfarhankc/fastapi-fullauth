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


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class VerifyEmailRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    refresh_token: str


def create_auth_router() -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.post("/register", response_model=UserSchema, status_code=201)
    async def register_route(
        data: CreateUserSchema,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        try:
            user = await register(fullauth.adapter, data)
        except UserAlreadyExistsError:
            raise USER_EXISTS_EXCEPTION
        return user

    @router.post("/login", response_model=TokenPair)
    async def login_route(
        request: Request,
        response: Response,
        fullauth: FullAuth = Depends(_get_fullauth),
        form_data: OAuth2PasswordRequestForm = Depends(),
    ):
        try:
            tokens = await login(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                email=form_data.username,
                password=form_data.password,
                lockout=fullauth.lockout,
            )
        except AccountLockedError:
            raise ACCOUNT_LOCKED_EXCEPTION
        except AuthenticationError:
            raise CREDENTIALS_EXCEPTION

        # write token to cookie if cookie backend is active
        for backend in fullauth.backends:
            await backend.write_token(response, tokens.access_token)

        return tokens

    @router.post("/logout", status_code=204)
    async def logout_route(
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ):
        try:
            payload = fullauth.token_engine.decode_token(token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        await logout(fullauth.token_engine, payload)

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
        access, refresh = fullauth.token_engine.create_token_pair(
            user_id=str(user.id), roles=roles
        )
        return TokenPair(access_token=access, refresh_token=refresh)

    @router.post("/verify-email/request", status_code=202)
    async def verify_email_request_route(
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
        token: str = Depends(_extract_token),
    ):
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
        try:
            await verify_email(fullauth.adapter, fullauth.token_engine, data.token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION
        return {"detail": "Email verified."}

    @router.post("/password-reset/request", status_code=202)
    async def password_reset_request_route(
        data: PasswordResetRequest,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        # always return 202 to prevent email enumeration
        await request_password_reset(fullauth.adapter, fullauth.token_engine, data.email)
        return {"detail": "If the email exists, a reset link has been sent."}

    @router.post("/password-reset/confirm", status_code=200)
    async def password_reset_confirm_route(
        data: PasswordResetConfirm,
        request: Request,
        fullauth: FullAuth = Depends(_get_fullauth),
    ):
        try:
            await reset_password(
                fullauth.adapter,
                fullauth.token_engine,
                data.token,
                data.new_password,
            )
        except TokenError:
            raise CREDENTIALS_EXCEPTION
        return {"detail": "Password has been reset."}

    return router
