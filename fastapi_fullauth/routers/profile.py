import logging
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from fastapi_fullauth.dependencies.current_user import CurrentUser, VerifiedUser, get_fullauth
from fastapi_fullauth.exceptions import (
    AuthenticationError,
    InvalidPasswordError,
    NoValidFieldsError,
    UnknownFieldsError,
)
from fastapi_fullauth.flows.change_password import change_password
from fastapi_fullauth.flows.profile import validate_profile_updates
from fastapi_fullauth.routers._schemas import (
    ChangePasswordRequest,
    MessageResponse,
    build_profile_update_model,
)
from fastapi_fullauth.types import UserSchema, UserSchemaType

logger = logging.getLogger("fastapi_fullauth.routers")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_profile_router(
    user_schema: type[UserSchemaType] = UserSchema,  # type: ignore[assignment]
    message_response_schema: type[MessageResponse] = MessageResponse,
) -> APIRouter:
    router = APIRouter()
    ProfileUpdate = build_profile_update_model(user_schema)  # noqa: N806

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
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: ProfileUpdate = Body(...),  # type: ignore[valid-type]
    ) -> UserSchema:
        raw = cast("BaseModel", data).model_dump(exclude_unset=True)
        try:
            updates = validate_profile_updates(raw, user_schema)
        except NoValidFieldsError:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        except UnknownFieldsError as e:
            raise HTTPException(status_code=422, detail=str(e))

        return await fullauth.adapter.update_user(user.id, updates)

    @router.delete("/me", status_code=204, description="Delete your own account.")
    async def delete_me_route(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> None:
        await fullauth.adapter.revoke_all_user_refresh_tokens(user.id)
        await fullauth.adapter.delete_user(user.id)
        logger.warning("Account deleted: user_id=%s, email=%s", user.id, user.email)

    @router.post(
        "/change-password",
        status_code=200,
        response_model=message_response_schema,
        description=(
            "Change password. `current_password` is required when the user already "
            "has one; for OAuth-only users without a stored password it may be omitted."
        ),
    )
    async def change_password_route(
        data: ChangePasswordRequest,
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        try:
            await change_password(
                adapter=fullauth.adapter,
                user_id=user.id,
                new_password=data.new_password,
                current_password=data.current_password,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
            )
        except AuthenticationError:
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        await fullauth.hooks.emit("after_password_change", user=user)
        return message_response_schema(detail="Password changed successfully.")

    return router
