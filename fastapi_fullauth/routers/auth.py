import contextlib
import logging
from typing import TYPE_CHECKING, cast
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from fastapi_fullauth.dependencies.current_user import _extract_token, get_fullauth
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
from fastapi_fullauth.flows.logout import logout
from fastapi_fullauth.flows.register import register
from fastapi_fullauth.flows.tokens import issue_token_pair
from fastapi_fullauth.routers._schemas import (
    LoginResponse,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    build_login_model,
    build_login_response_model,
)
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    TokenPair,
    UserSchema,
    UserSchemaType,
)

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
            "Create a new user account. Returns 201 + user by default. "
            "Setting `PREVENT_REGISTRATION_ENUMERATION=True` makes it always "
            "return 202 + a generic message so attackers can't probe whether "
            "an email is registered."
        ),
    )
    async def register_route(
        request: Request,
        response: Response,
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: create_user_schema = Body(...),  # type: ignore[valid-type]
    ) -> UserSchema | MessageResponse:
        await fullauth.enforce_rate_limit(request, "register")

        anti_enum = fullauth.config.PREVENT_REGISTRATION_ENUMERATION
        generic = message_response_schema(
            detail="If this email isn't already registered, a verification email has been sent."
        )

        try:
            user = await register(
                fullauth.adapter,
                data,
                login_field=login_field,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
            )
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except UserAlreadyExistsError:
            if anti_enum:
                response.status_code = 202
                return generic
            raise USER_EXISTS_EXCEPTION

        await fullauth.hooks.emit("after_register", user=user)

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
        extra_claims = await fullauth.get_custom_claims(user) if user else {}

        try:
            tokens = await login(
                adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
                identifier=identifier,
                password=password,
                login_field=login_field,
                lockout=fullauth.lockout,
                extra_claims=extra_claims,
                user=user,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                prevent_timing_attacks=fullauth.config.PREVENT_LOGIN_TIMING_ATTACKS,
            )
        except (AccountLockedError, AuthenticationError):
            raise CREDENTIALS_EXCEPTION

        for backend in fullauth.backends:
            await backend.write_token(response, tokens.access_token)

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
        data: RefreshRequest,
        request: Request,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> TokenPair:
        await fullauth.enforce_rate_limit(request, "refresh")

        try:
            payload = await fullauth.token_engine.decode_token(data.refresh_token)
        except TokenError:
            raise CREDENTIALS_EXCEPTION

        if payload.type != "refresh":
            raise CREDENTIALS_EXCEPTION

        try:
            user_id = UUID(payload.sub)
        except ValueError:
            raise CREDENTIALS_EXCEPTION

        user = await fullauth.adapter.get_user_by_id(user_id)
        if user is None or not user.is_active:
            raise CREDENTIALS_EXCEPTION

        stored = await fullauth.adapter.get_refresh_token(data.refresh_token)
        # Defence in depth: the refresh JWT may decode cleanly (valid signature,
        # unexpired) and still not correspond to a stored session = e.g. an old
        # row pruned, or a token issued before the row was deleted. Reject so
        # signed-but-unbacked tokens can't mint new access tokens.
        if stored is None:
            raise CREDENTIALS_EXCEPTION

        roles = await fullauth.adapter.get_user_roles(user.id)
        extra_claims = await fullauth.get_custom_claims(user)
        uid = str(user.id)

        if fullauth.config.REFRESH_TOKEN_ROTATION:
            # Compare-and-swap: exactly one concurrent caller flips the token
            # from not-revoked → revoked. The loser sees rowcount=0 = that's
            # either a reuse attack or a lost concurrency race. Either way,
            # burn the family.
            won = await fullauth.adapter.revoke_refresh_token(data.refresh_token)
            if not won:
                logger.error(
                    "refresh token reuse/concurrent use = revoking family: %s",
                    stored.family_id,
                )
                await fullauth.adapter.revoke_refresh_token_family(stored.family_id)
                raise CREDENTIALS_EXCEPTION
            await fullauth.token_engine.blacklist_token(
                payload.jti,
                ttl_seconds=fullauth.config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            )

            return await issue_token_pair(
                fullauth.adapter,
                fullauth.token_engine,
                user,
                extra_claims=extra_claims,
                family_id=payload.family_id,
                roles=roles,
            )

        if stored.revoked:
            raise CREDENTIALS_EXCEPTION
        access = fullauth.token_engine.create_access_token(
            user_id=uid,
            roles=roles,
            extra=extra_claims,
        )
        return TokenPair(
            access_token=access,
            refresh_token=data.refresh_token,
            expires_in=fullauth.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @router.post(
        "/logout",
        status_code=204,
        description="Blacklist token. Pass refresh_token in body to revoke the session.",
    )
    async def logout_route(
        fullauth: "FullAuth" = Depends(get_fullauth),
        token: str = Depends(_extract_token),
        data: LogoutRequest | None = Body(None),
    ) -> Response:
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
        with contextlib.suppress(ValueError):
            await fullauth.hooks.emit("after_logout", user_id=UUID(payload.sub))

        response = Response(status_code=204)
        for backend in fullauth.backends:
            await backend.delete_token(response)
        return response

    return router
