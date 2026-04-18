import logging
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from fastapi_fullauth.adapters.base import PasskeyAdapterMixin
from fastapi_fullauth.dependencies.current_user import CurrentUser, _get_fullauth
from fastapi_fullauth.router._models import build_login_response_model
from fastapi_fullauth.types import TokenPair, UserSchema, UserSchemaType

logger = logging.getLogger("fastapi_fullauth.router.passkey")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


class RegisterCompleteRequest(BaseModel):
    challenge_key: str
    credential: dict
    device_name: str = ""


class AuthenticateBeginRequest(BaseModel):
    email: str | None = None


class AuthenticateCompleteRequest(BaseModel):
    challenge_key: str
    credential: dict


class PasskeyResponse(BaseModel):
    id: UUID
    device_name: str
    transports: list[str]
    backed_up: bool
    created_at: str | None = None
    last_used_at: str | None = None


def create_passkey_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
) -> APIRouter:
    LoginResponse = build_login_response_model(user_schema)  # noqa: N806
    router = APIRouter()

    @router.post(
        "/passkeys/register/begin",
        status_code=200,
        description="Begin passkey registration. Returns WebAuthn creation options.",
    )
    async def register_begin(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> dict:
        from fastapi_fullauth.flows.passkey import begin_registration

        if not fullauth.config.PASSKEY_ENABLED:
            raise HTTPException(status_code=404, detail="Passkeys are not enabled")

        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        return await begin_registration(
            user=user,
            rp_id=fullauth.config.PASSKEY_RP_ID,
            rp_name=fullauth.config.PASSKEY_RP_NAME or fullauth.config.PASSKEY_RP_ID,
            challenge_store=fullauth.challenge_store,
            adapter=fullauth.adapter,
            challenge_ttl=fullauth.config.PASSKEY_CHALLENGE_TTL,
        )

    @router.post(
        "/passkeys/register/complete",
        status_code=201,
        description="Complete passkey registration. Verifies attestation and stores credential.",
    )
    async def register_complete(
        user: CurrentUser,
        data: RegisterCompleteRequest,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> PasskeyResponse:
        from fastapi_fullauth.flows.passkey import complete_registration

        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        origins = fullauth.config.PASSKEY_ORIGINS
        if not origins:
            raise HTTPException(status_code=500, detail="PASSKEY_ORIGINS not configured")

        try:
            passkey = await complete_registration(
                challenge_key=data.challenge_key,
                credential=data.credential,
                device_name=data.device_name,
                user=user,
                rp_id=fullauth.config.PASSKEY_RP_ID,
                expected_origin=origins,
                challenge_store=fullauth.challenge_store,
                adapter=fullauth.adapter,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error("Passkey registration failed: %s", e)
            raise HTTPException(status_code=400, detail="Passkey registration failed")

        return PasskeyResponse(
            id=passkey.id,
            device_name=passkey.device_name,
            transports=passkey.transports,
            backed_up=passkey.backed_up,
            created_at=passkey.created_at.isoformat() if passkey.created_at else None,
            last_used_at=None,
        )

    @router.post(
        "/passkeys/authenticate/begin",
        status_code=200,
        description="Begin passkey authentication. Returns WebAuthn request options.",
    )
    async def authenticate_begin(
        data: AuthenticateBeginRequest = Body(AuthenticateBeginRequest()),
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> dict:
        from fastapi_fullauth.flows.passkey import begin_authentication

        if not fullauth.config.PASSKEY_ENABLED:
            raise HTTPException(status_code=404, detail="Passkeys are not enabled")

        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        user_id = None
        if data.email:
            user = await fullauth.adapter.get_user_by_email(data.email)
            if user:
                user_id = user.id

        return await begin_authentication(
            rp_id=fullauth.config.PASSKEY_RP_ID,
            challenge_store=fullauth.challenge_store,
            adapter=fullauth.adapter,
            user_id=user_id,
            challenge_ttl=fullauth.config.PASSKEY_CHALLENGE_TTL,
        )

    @router.post(
        "/passkeys/authenticate/complete",
        status_code=200,
        response_model=LoginResponse,
        description="Complete passkey authentication. Returns JWT tokens.",
    )
    async def authenticate_complete(
        data: AuthenticateCompleteRequest,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> TokenPair:
        from fastapi_fullauth.flows.passkey import complete_authentication

        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        origins = fullauth.config.PASSKEY_ORIGINS
        if not origins:
            raise HTTPException(status_code=500, detail="PASSKEY_ORIGINS not configured")

        try:
            token_pair, user = await complete_authentication(
                challenge_key=data.challenge_key,
                credential=data.credential,
                rp_id=fullauth.config.PASSKEY_RP_ID,
                expected_origin=origins,
                challenge_store=fullauth.challenge_store,
                adapter=fullauth.adapter,
                passkey_adapter=fullauth.adapter,
                token_engine=fullauth.token_engine,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error("Passkey authentication failed: %s", e)
            raise HTTPException(status_code=401, detail="Passkey authentication failed")

        await fullauth.hooks.emit("after_login", user=user)

        if fullauth.config.INCLUDE_USER_IN_LOGIN and user:
            return LoginResponse(
                access_token=token_pair.access_token,
                refresh_token=token_pair.refresh_token,
                token_type=token_pair.token_type,
                expires_in=token_pair.expires_in,
                user=user,
            )

        return token_pair

    @router.get(
        "/passkeys",
        status_code=200,
        response_model=list[PasskeyResponse],
        description="List all registered passkeys for the current user.",
    )
    async def list_passkeys(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> list[PasskeyResponse]:
        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        passkeys = await fullauth.adapter.get_user_passkeys(user.id)
        return [
            PasskeyResponse(
                id=pk.id,
                device_name=pk.device_name,
                transports=pk.transports,
                backed_up=pk.backed_up,
                created_at=pk.created_at.isoformat() if pk.created_at else None,
                last_used_at=pk.last_used_at.isoformat() if pk.last_used_at else None,
            )
            for pk in passkeys
        ]

    @router.delete(
        "/passkeys/{passkey_id}",
        status_code=204,
        description="Delete a registered passkey.",
    )
    async def delete_passkey(
        passkey_id: UUID,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> None:
        if not isinstance(fullauth.adapter, PasskeyAdapterMixin):
            raise HTTPException(status_code=501, detail="Adapter does not support passkeys")

        passkeys = await fullauth.adapter.get_user_passkeys(user.id)
        if not any(pk.id == passkey_id for pk in passkeys):
            raise HTTPException(status_code=404, detail="Passkey not found")

        await fullauth.adapter.delete_passkey(passkey_id)
        logger.info("Passkey deleted: user_id=%s, passkey_id=%s", user.id, passkey_id)

    return router
