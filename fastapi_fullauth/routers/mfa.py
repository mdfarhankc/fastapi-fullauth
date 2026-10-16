import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from fastapi_fullauth.adapters.base import MFAAdapterMixin
from fastapi_fullauth.dependencies.current_user import (
    CurrentUser,
    current_token_payload,
    get_fullauth,
)
from fastapi_fullauth.exceptions import AuthenticationError
from fastapi_fullauth.flows import mfa as mfa_flow
from fastapi_fullauth.flows.reauth import verify_recent_auth
from fastapi_fullauth.routers._schemas import LoginResponse, MessageResponse
from fastapi_fullauth.types import TokenPair, TokenPayload, UserSchema, UserSchemaType

logger = logging.getLogger("fastapi_fullauth.routers.mfa")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth

# Purpose of the token handed out between a correct password and a valid code.
PENDING_PURPOSE = "mfa_pending"


class EnrollResponse(BaseModel):
    secret: str = Field(description="Enter this manually if the QR code cannot be scanned.")
    provisioning_uri: str = Field(
        description="otpauth:// URI for the QR code. Contains the secret; never log it."
    )


class MFARequiredResponse(BaseModel):
    """What a correct password returns when the account has a second factor."""

    mfa_required: bool = True
    mfa_token: str = Field(
        description="Short-lived; buys only the right to submit a code at /mfa/verify."
    )


class CodeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=64)


class ConfirmResponse(BaseModel):
    recovery_codes: list[str] = Field(
        description=(
            "Shown once and never again. Each works instead of a code, one time, "
            "for a user who has lost their authenticator."
        )
    )


class MFAStatusResponse(BaseModel):
    enabled: bool
    recovery_codes_remaining: int


class VerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=1, max_length=64)


def _require_adapter(fullauth: "FullAuth") -> None:
    if not fullauth.config.MFA_ENABLED:
        raise HTTPException(status_code=404, detail="Two-factor authentication is not enabled")
    if not fullauth.adapter.supports_feature("mfa") or not isinstance(
        fullauth.adapter, MFAAdapterMixin
    ):
        raise HTTPException(status_code=501, detail="Adapter does not support two-factor")


async def _prove_presence(
    fullauth: "FullAuth", user: UserSchema, payload: TokenPayload, current_password: str | None
) -> None:
    """Adding or removing a second factor is an account-security action."""
    try:
        await verify_recent_auth(
            payload,
            hashed_password=await fullauth.adapter.get_hashed_password(user.id),
            current_password=current_password,
            max_age_seconds=fullauth.config.REAUTH_MAX_AGE_SECONDS,
            max_password_length=fullauth.config.PASSWORD_MAX_LENGTH,
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e


class EnrollRequest(BaseModel):
    current_password: str | None = None


def create_mfa_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
    login_response_schema: type[LoginResponse] = LoginResponse,
    message_response_schema: type[MessageResponse] = MessageResponse,
) -> APIRouter:
    from fastapi_fullauth.routers._schemas import build_login_response_model

    LoginResponse = build_login_response_model(user_schema, base=login_response_schema)  # noqa: N806
    router = APIRouter()

    @router.get(
        "/mfa",
        status_code=200,
        response_model=MFAStatusResponse,
        description=(
            "Whether two-factor authentication is on, and how many recovery codes remain."
        ),
    )
    async def status_route(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MFAStatusResponse:
        _require_adapter(fullauth)
        adapter = fullauth.adapter
        assert isinstance(adapter, MFAAdapterMixin)
        credential = await adapter.get_mfa(user.id)
        if credential is None or not credential.is_confirmed:
            return MFAStatusResponse(enabled=False, recovery_codes_remaining=0)
        return MFAStatusResponse(
            enabled=True, recovery_codes_remaining=len(credential.recovery_codes)
        )

    @router.post(
        "/mfa/enroll",
        status_code=200,
        response_model=EnrollResponse,
        description=(
            "Start enrolment. Returns a secret and its provisioning URI; neither does "
            "anything until confirmed with a valid code. Needs proof of presence: "
            "`current_password`, or a session whose credentials were checked within "
            "`REAUTH_MAX_AGE_SECONDS`."
        ),
    )
    async def enroll_route(
        user: CurrentUser,
        payload: TokenPayload = Depends(current_token_payload),
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: EnrollRequest | None = Body(None),
    ) -> EnrollResponse:
        _require_adapter(fullauth)
        await _prove_presence(fullauth, user, payload, data.current_password if data else None)

        issuer = fullauth.config.MFA_ISSUER or "fastapi-fullauth"
        try:
            secret, uri = await mfa_flow.begin_enrollment(fullauth.adapter, user, issuer)
        except AuthenticationError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return EnrollResponse(secret=secret, provisioning_uri=uri)

    @router.post(
        "/mfa/confirm",
        status_code=200,
        response_model=ConfirmResponse,
        description=(
            "Finish enrolment with a code from the authenticator. Returns the recovery "
            "codes, which are shown once and stored hashed."
        ),
    )
    async def confirm_route(
        data: CodeRequest,
        request: Request,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> ConfirmResponse:
        _require_adapter(fullauth)
        await fullauth.enforce_rate_limit(request, "mfa")
        try:
            codes = await mfa_flow.confirm_enrollment(fullauth.adapter, user, data.code)
        except AuthenticationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        await fullauth.hooks.emit("after_mfa_enabled", user=user)
        return ConfirmResponse(recovery_codes=codes)

    @router.delete(
        "/mfa",
        status_code=204,
        description=(
            "Turn two-factor authentication off. Needs the same proof of presence as "
            "enrolling, since it removes a protection."
        ),
    )
    async def disable_route(
        user: CurrentUser,
        payload: TokenPayload = Depends(current_token_payload),
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: EnrollRequest | None = Body(None),
    ) -> None:
        _require_adapter(fullauth)
        await _prove_presence(fullauth, user, payload, data.current_password if data else None)
        await mfa_flow.disable(fullauth.adapter, user.id)
        await fullauth.hooks.emit("after_mfa_disabled", user=user)

    @router.post(
        "/mfa/verify",
        status_code=200,
        response_model=LoginResponse,
        description=(
            "Exchange the token from a password sign-in, plus a code or a recovery "
            "code, for the real token pair."
        ),
    )
    async def verify_route(
        data: VerifyRequest,
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> TokenPair:
        from fastapi_fullauth.exceptions import CREDENTIALS_EXCEPTION, TokenError
        from fastapi_fullauth.flows.tokens import issue_token_pair
        from fastapi_fullauth.routers._transport import write_tokens
        from fastapi_fullauth.utils import request_session_metadata

        _require_adapter(fullauth)
        # Six digits is a small space, so the attempts are metered before any
        # work, and counted against the account as well as the caller's address.
        await fullauth.enforce_rate_limit(request, "mfa")

        try:
            payload = await fullauth.token_engine.decode_token(
                data.mfa_token, expected_type="access", expected_purpose=PENDING_PURPOSE
            )
            user_id = fullauth.adapter.parse_user_id(payload.sub)
        except (TokenError, ValueError):
            raise CREDENTIALS_EXCEPTION from None

        lockout_key = f"mfa:{user_id}"
        if fullauth.lockout and await fullauth.lockout.is_locked(lockout_key):
            logger.warning("MFA blocked; too many failures: user_id=%s", user_id)
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(user_id)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        try:
            await mfa_flow.verify_code(fullauth.adapter, user_id, data.code)
        except AuthenticationError:
            if fullauth.lockout:
                await fullauth.lockout.record_failure(lockout_key)
            raise CREDENTIALS_EXCEPTION from None

        if fullauth.lockout:
            await fullauth.lockout.clear(lockout_key)
        # Single use: the pending token cannot buy a second session.
        await fullauth.token_engine.blacklist_payload(payload)

        user_agent, ip_address = request_session_metadata(
            request, fullauth.config.TRUSTED_PROXY_HEADERS, fullauth.config.TRUSTED_PROXY_COUNT
        )
        tokens = await issue_token_pair(
            fullauth.adapter,
            fullauth.token_engine,
            user,
            extra_claims=await fullauth.get_custom_claims(user),
            user_agent=user_agent,
            ip_address=ip_address,
        )
        tokens = await write_tokens(response, fullauth, tokens)
        await fullauth.hooks.emit("after_login", user=user)
        logger.info("MFA sign-in completed: user_id=%s", user_id)

        return LoginResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            user=user,
        )

    return router
