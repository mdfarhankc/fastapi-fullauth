import contextlib
import logging
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from fastapi_fullauth.core.crypto import ahash_password
from fastapi_fullauth.dependencies.current_user import _extract_optional_token, get_fullauth
from fastapi_fullauth.exceptions import (
    CREDENTIALS_EXCEPTION,
    USER_EXISTS_EXCEPTION,
    AccountLockedError,
    AuthenticationError,
    InvalidPasswordError,
    TokenError,
    UserAlreadyExistsError,
)
from fastapi_fullauth.flows.login import login
from fastapi_fullauth.flows.logout import logout, logout_with_refresh_token
from fastapi_fullauth.flows.refresh import refresh
from fastapi_fullauth.flows.register import register
from fastapi_fullauth.routers._schemas import (
    LoginResponse,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    build_login_model,
    build_login_response_model,
)
from fastapi_fullauth.routers._transport import resolve_refresh_token, write_tokens
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    TokenPair,
    TokenPayload,
    UserSchema,
    UserSchemaType,
)
from fastapi_fullauth.utils import request_session_metadata

logger = logging.getLogger("fastapi_fullauth.router")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_auth_router(
    create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
    login_field: str = "email",
    login_response_schema: type[LoginResponse] = LoginResponse,
    message_response_schema: type[MessageResponse] = MessageResponse,
) -> APIRouter:
    LoginRequest = build_login_model(login_field)  # noqa: N806
    LoginResponse = build_login_response_model(user_schema, base=login_response_schema)  # noqa: N806
    router = APIRouter()

    @router.post(
        "/register",
        status_code=201,
        response_model=user_schema | message_response_schema,
        description=(
            "Create a new user account. Returns 202 + a generic message by "
            "default (`PREVENT_REGISTRATION_ENUMERATION=True`) so attackers "
            "can't probe whether an email is registered. Set it to `False` "
            "for 201 + the created user, and 409 on a duplicate email. "
            "No verification email is sent from here; send one from the "
            "`after_register` hook if you want that."
        ),
    )
    async def register_route(
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: create_user_schema = Body(...),  # type: ignore[valid-type]
    ) -> UserSchema | MessageResponse:
        await fullauth.enforce_rate_limit(request, "register")

        anti_enum = fullauth.config.PREVENT_REGISTRATION_ENUMERATION
        hash_algorithm = fullauth.config.PASSWORD_HASH_ALGORITHM
        generic = message_response_schema(
            detail="If this email isn't already registered, the account has been created."
        )

        try:
            user = await register(
                fullauth.adapter,
                data,
                login_field=login_field,
                hash_algorithm=hash_algorithm,
                password_validator=fullauth.password_validator,
            )
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except UserAlreadyExistsError:
            if not anti_enum:
                raise USER_EXISTS_EXCEPTION
            # A new account pays for a password hash; without the same work here
            # the response time reveals that the email is already registered.
            try:
                await ahash_password(cast("CreateUserSchema", data).password, hash_algorithm)
            except InvalidPasswordError as e:
                raise HTTPException(status_code=422, detail=str(e))
            response.status_code = 202
            return generic

        # Run after the response is sent, so hook latency (typically an email
        # send) cannot reveal that an account was created.
        background_tasks.add_task(fullauth.hooks.emit, "after_register", user=user)

        if anti_enum:
            response.status_code = 202
            return generic
        return user

    @router.post(
        "/login",
        status_code=200,
        response_model=LoginResponse,
        description="Authenticate and get access + refresh tokens.",
    )
    async def login_route(
        data: LoginRequest,  # type: ignore[valid-type]
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> TokenPair:
        await fullauth.enforce_rate_limit(request, "login")

        # LoginRequest is built dynamically via create_model from `login_field`
        # and "password", so static type checkers can't see either field. Go
        # through model_dump() (typed via the BaseModel cast) and pluck both.
        fields = cast("BaseModel", data).model_dump()
        identifier: str = fields[login_field]
        password: str = fields["password"]
        user = await fullauth.adapter.get_user_by_field(login_field, identifier)
        user_agent, ip_address = request_session_metadata(
            request, fullauth.config.TRUSTED_PROXY_HEADERS, fullauth.config.TRUSTED_PROXY_COUNT
        )

        try:
            tokens = await login(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                identifier=identifier,
                password=password,
                login_field=login_field,
                lockout=fullauth.lockout,
                extra_claims_provider=fullauth.get_custom_claims,
                user=user,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                prevent_timing_attacks=fullauth.config.PREVENT_LOGIN_TIMING_ATTACKS,
                max_password_length=fullauth.config.PASSWORD_MAX_LENGTH,
                user_agent=user_agent,
                ip_address=ip_address,
            )
        except (AccountLockedError, AuthenticationError):
            raise CREDENTIALS_EXCEPTION

        tokens = await write_tokens(response, fullauth, tokens)

        await fullauth.hooks.emit("after_login", user=user)

        if user is not None:
            return LoginResponse(
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
                token_type=tokens.token_type,
                expires_in=tokens.expires_in,
                user=user,
            )

        return tokens

    @router.post(
        "/refresh",
        status_code=200,
        response_model=TokenPair,
        description="Rotate token pair. Reuse of old tokens revokes the session.",
    )
    async def refresh_route(
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: RefreshRequest | None = Body(None),
    ) -> TokenPair:
        await fullauth.enforce_rate_limit(request, "refresh")

        refresh_token = await resolve_refresh_token(
            request, fullauth, data.refresh_token if data else None
        )
        if refresh_token is None:
            raise CREDENTIALS_EXCEPTION

        user_agent, ip_address = request_session_metadata(
            request, fullauth.config.TRUSTED_PROXY_HEADERS, fullauth.config.TRUSTED_PROXY_COUNT
        )

        try:
            tokens = await refresh(
                fullauth.adapter,
                fullauth.token_engine,
                refresh_token,
                extra_claims_provider=fullauth.get_custom_claims,
                user_agent=user_agent,
                ip_address=ip_address,
            )
        except (TokenError, AuthenticationError):
            raise CREDENTIALS_EXCEPTION

        return await write_tokens(response, fullauth, tokens)

    @router.post(
        "/logout",
        status_code=204,
        description=(
            "End the current session. Uses the access token when it is valid; otherwise "
            "the refresh token (cookie or body), so a client whose access token expired "
            "can still sign out. Token cookies are cleared on every outcome."
        ),
    )
    async def logout_route(
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
        token: str | None = Depends(_extract_optional_token),
        data: LogoutRequest | None = Body(None),
    ) -> Response:
        refresh_token = await resolve_refresh_token(
            request, fullauth, data.refresh_token if data else None
        )
        payload = await _session_payload(fullauth, token)
        try:
            if payload is not None:
                await logout(
                    fullauth.token_engine,
                    payload,
                    adapter=fullauth.adapter,
                    refresh_token=refresh_token,
                )
            elif refresh_token is not None:
                payload = await logout_with_refresh_token(
                    fullauth.adapter, fullauth.token_engine, refresh_token
                )
            else:
                return await _clear_token_cookies(fullauth, _credentials_error())
        except (TokenError, AuthenticationError):
            return await _clear_token_cookies(fullauth, _credentials_error())

        with contextlib.suppress(ValueError, ValidationError):
            await fullauth.hooks.emit(
                "after_logout", user_id=fullauth.adapter.parse_user_id(payload.sub)
            )
        return await _clear_token_cookies(fullauth, Response(status_code=204))

    return router


async def _session_payload(fullauth: "FullAuth", token: str | None) -> TokenPayload | None:
    """Decode a session access token, or None when it is missing or unusable.

    Purpose-scoped tokens (password reset, email verification) are access-typed
    but are not session credentials, so they count as unusable.
    """
    if token is None:
        return None
    try:
        payload = await fullauth.token_engine.decode_token(token, expected_type="access")
    except TokenError:
        return None
    return None if payload.extra.get("purpose") else payload


def _credentials_error() -> JSONResponse:
    return JSONResponse(
        {"detail": CREDENTIALS_EXCEPTION.detail},
        status_code=CREDENTIALS_EXCEPTION.status_code,
        headers=CREDENTIALS_EXCEPTION.headers,
    )


async def _clear_token_cookies(fullauth: "FullAuth", response: Response) -> Response:
    for backend in fullauth.backends:
        await backend.delete_token(response)
        await backend.delete_refresh_token(response)
    return response
