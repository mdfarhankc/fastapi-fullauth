import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response

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
from fastapi_fullauth.flows.login import login
from fastapi_fullauth.flows.logout import logout
from fastapi_fullauth.flows.register import register
from fastapi_fullauth.router._models import LogoutRequest, RefreshRequest, build_login_model
from fastapi_fullauth.types import (
    CreateUserSchema,
    CreateUserSchemaType,
    RefreshToken,
    TokenPair,
    UserSchema,
    UserSchemaType,
)
from fastapi_fullauth.utils import get_client_ip

logger = logging.getLogger("fastapi_fullauth.router")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_auth_router(
    create_user_schema: type[CreateUserSchemaType] = CreateUserSchema,  # type: ignore[assignment]
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
    login_field: str = "email",
) -> APIRouter:
    LoginRequest = build_login_model(login_field)  # noqa: N806
    router = APIRouter()

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
        client_ip = get_client_ip(request, fullauth.config.TRUSTED_PROXY_HEADERS)
        await fullauth.check_auth_rate_limit("register", client_ip)

        try:
            fullauth.password_validator.validate(data.password)
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        try:
            user = await register(
                fullauth.adapter,
                data,
                login_field=login_field,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
            )
        except UserAlreadyExistsError:
            raise USER_EXISTS_EXCEPTION

        await fullauth.hooks.emit("after_register", user=user)
        return user

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
        client_ip = get_client_ip(request, fullauth.config.TRUSTED_PROXY_HEADERS)
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
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
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

        stored = await fullauth.adapter.get_refresh_token(data.refresh_token)
        if stored is not None and stored.revoked:
            logger.error(
                "Refresh token reuse detected — revoking family: %s",
                stored.family_id,
            )
            await fullauth.adapter.revoke_refresh_token_family(stored.family_id)
            raise CREDENTIALS_EXCEPTION

        roles = await fullauth.adapter.get_user_roles(user.id)
        extra_claims = await fullauth.get_custom_claims(user)
        uid = str(user.id)

        if fullauth.config.REFRESH_TOKEN_ROTATION:
            already_blacklisted = await fullauth.token_engine.blacklist.is_blacklisted(payload.jti)
            if already_blacklisted:
                logger.warning(
                    "Concurrent refresh token use detected: jti=%s",
                    payload.jti,
                )
                if stored is not None:
                    await fullauth.adapter.revoke_refresh_token_family(stored.family_id)
                raise CREDENTIALS_EXCEPTION
            await fullauth.token_engine.blacklist_token(
                payload.jti,
                ttl_seconds=fullauth.config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            )
            if stored is not None:
                await fullauth.adapter.revoke_refresh_token(data.refresh_token)

            access, refresh_meta = fullauth.token_engine.create_token_pair(
                user_id=uid,
                roles=roles,
                extra=extra_claims,
                family_id=payload.family_id,
            )

            await fullauth.adapter.store_refresh_token(
                RefreshToken(
                    token=refresh_meta.token,
                    user_id=uid,
                    expires_at=refresh_meta.expires_at,
                    family_id=refresh_meta.family_id,
                )
            )
            refresh_token = refresh_meta.token
        else:
            access = fullauth.token_engine.create_access_token(
                user_id=uid,
                roles=roles,
                extra=extra_claims,
            )
            refresh_token = data.refresh_token

        return TokenPair(
            access_token=access,
            refresh_token=refresh_token,
            expires_in=fullauth.config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

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

    return router
