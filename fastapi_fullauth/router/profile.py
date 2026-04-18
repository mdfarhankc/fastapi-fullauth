import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException

from fastapi_fullauth.dependencies.current_user import CurrentUser, VerifiedUser, _get_fullauth
from fastapi_fullauth.exceptions import (
    AuthenticationError,
    InvalidPasswordError,
    NoValidFieldsError,
    UnknownFieldsError,
)
from fastapi_fullauth.flows.change_password import change_password
from fastapi_fullauth.flows.set_password import set_password
from fastapi_fullauth.flows.update_profile import validate_profile_updates
from fastapi_fullauth.router._models import (
    ChangePasswordRequest,
    MessageResponse,
    SetPasswordRequest,
)
from fastapi_fullauth.types import UserSchema, UserSchemaType

logger = logging.getLogger("fastapi_fullauth.router")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_profile_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
) -> APIRouter:
    router = APIRouter()

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
        try:
            updates = validate_profile_updates(data, user_schema)
        except NoValidFieldsError:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        except UnknownFieldsError as e:
            raise HTTPException(status_code=422, detail=str(e))

        return await fullauth.adapter.update_user(user.id, updates)

    @router.delete("/me", status_code=204, description="Delete your own account.")
    async def delete_me_route(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> None:
        await fullauth.adapter.revoke_all_user_refresh_tokens(user.id)
        await fullauth.adapter.delete_user(user.id)
        logger.warning("Account deleted: user_id=%s, email=%s", user.id, user.email)

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
        try:
            await change_password(
                adapter=fullauth.adapter,
                user_id=user.id,
                current_password=data.current_password,
                new_password=data.new_password,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
            )
        except AuthenticationError:
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        await fullauth.hooks.emit("after_password_change", user=user)
        return MessageResponse(detail="Password changed successfully.")

    @router.post(
        "/set-password",
        status_code=200,
        response_model=MessageResponse,
        description="Set a password for OAuth-only users who don't have one.",
    )
    async def set_password_route(
        data: SetPasswordRequest,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        try:
            await set_password(
                adapter=fullauth.adapter,
                user_id=user.id,
                new_password=data.new_password,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
            )
        except AuthenticationError:
            raise HTTPException(
                status_code=400,
                detail="You already have a password. Use change-password instead.",
            )
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        return MessageResponse(detail="Password set successfully.")

    return router
