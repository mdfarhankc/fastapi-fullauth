import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request

from fastapi_fullauth.dependencies.current_user import CurrentUser, get_fullauth
from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION, InvalidPasswordError, TokenError
from fastapi_fullauth.flows.email_verify import create_email_verification_token, verify_email
from fastapi_fullauth.flows.password_reset import request_password_reset, reset_password
from fastapi_fullauth.routers._schemas import (
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    VerifyEmailRequest,
)

logger = logging.getLogger("fastapi_fullauth.routers")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_verify_router() -> APIRouter:
    router = APIRouter()

    @router.post(
        "/verify-email/request",
        status_code=202,
        response_model=MessageResponse,
        description="Send a verification email to the current user.",
    )
    async def verify_email_request_route(
        user: CurrentUser,
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        await fullauth.enforce_rate_limit(request, "password-reset")

        verify_token = await create_email_verification_token(
            fullauth.adapter, fullauth.token_engine, user.id
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
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        await fullauth.enforce_rate_limit(request, "password-reset")

        try:
            user = await verify_email(fullauth.adapter, fullauth.token_engine, data.token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if user:
            await fullauth.hooks.emit("after_email_verify", user=user)

        return MessageResponse(detail="Email verified.")

    @router.post(
        "/password-reset/request",
        status_code=202,
        response_model=MessageResponse,
        description="Request a password reset email.",
    )
    async def password_reset_request_route(
        data: PasswordResetRequest,
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        await fullauth.enforce_rate_limit(request, "password-reset")

        token = await request_password_reset(fullauth.adapter, fullauth.token_engine, data.email)

        if token:
            await fullauth.hooks.emit("send_password_reset_email", email=data.email, token=token)

        return MessageResponse(detail="If the email exists, a reset link has been sent.")

    @router.post(
        "/password-reset/confirm",
        status_code=200,
        response_model=MessageResponse,
        description="Set a new password using the reset token.",
    )
    async def password_reset_confirm_route(
        data: PasswordResetConfirm,
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        await fullauth.enforce_rate_limit(request, "password-reset")

        try:
            user = await reset_password(
                fullauth.adapter,
                fullauth.token_engine,
                data.token,
                data.new_password,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
            )
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if user:
            await fullauth.hooks.emit("after_password_reset", user=user)

        return MessageResponse(detail="Password has been reset.")

    return router
