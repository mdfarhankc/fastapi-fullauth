import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Body, Depends, HTTPException, Response

from fastapi_fullauth.core.crypto import hash_password, verify_password
from fastapi_fullauth.dependencies.current_user import CurrentUser, VerifiedUser, _get_fullauth
from fastapi_fullauth.exceptions import InvalidPasswordError
from fastapi_fullauth.router._models import ChangePasswordRequest, MessageResponse
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
        protected = {
            "id",
            "email",
            "hashed_password",
            "is_active",
            "is_verified",
            "is_superuser",
            "roles",
            "password",
            "created_at",
            "refresh_tokens",
        }
        updates = {k: v for k, v in data.items() if k not in protected}
        if not updates:
            raise HTTPException(status_code=400, detail="No valid fields to update")

        allowed = set(user_schema.model_fields.keys()) - protected
        unknown = set(updates.keys()) - allowed
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown fields: {', '.join(sorted(unknown))}",
            )

        return await fullauth.adapter.update_user(user.id, updates)

    @router.delete("/me", status_code=204, description="Delete your own account.")
    async def delete_me_route(
        user: CurrentUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> None:
        await fullauth.adapter.revoke_all_user_refresh_tokens(user.id)
        await fullauth.adapter.delete_user(user.id)
        logger.warning("Account deleted: user_id=%s, email=%s", user.id, user.email)
        return Response(status_code=204)

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
        hashed = await fullauth.adapter.get_hashed_password(user.id)
        if hashed is None or not verify_password(data.current_password, hashed):
            logger.warning(
                "Password change failed — wrong current password: user_id=%s", user.id
            )
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        try:
            fullauth.password_validator.validate(data.new_password)
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        new_hash = hash_password(
            data.new_password,
            algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
        )
        await fullauth.adapter.set_password(user.id, new_hash)
        await fullauth.adapter.revoke_all_user_refresh_tokens(user.id)
        logger.info("Password changed: user_id=%s", user.id)
        await fullauth.hooks.emit("after_password_change", user=user)
        return MessageResponse(detail="Password changed successfully.")

    return router
