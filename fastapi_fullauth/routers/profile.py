import logging
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError

from fastapi_fullauth.dependencies.current_user import (
    CurrentUser,
    VerifiedUser,
    current_token_payload,
    get_fullauth,
)
from fastapi_fullauth.exceptions import (
    AuthenticationError,
    InvalidPasswordError,
    NoValidFieldsError,
    UnknownFieldsError,
)
from fastapi_fullauth.flows.change_password import change_password
from fastapi_fullauth.flows.profile import validate_profile_updates
from fastapi_fullauth.flows.reauth import verify_recent_auth
from fastapi_fullauth.routers._schemas import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    MessageResponse,
    build_profile_update_model,
)
from fastapi_fullauth.types import TokenPayload, UserSchema, UserSchemaType

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
            updates = validate_profile_updates(raw, user_schema, current=user)
        except NoValidFieldsError:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        except UnknownFieldsError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except ValidationError as e:
            # Same 422 shape FastAPI uses for request body validation.
            raise RequestValidationError(e.errors(include_url=False))

        return await fullauth.adapter.update_user(user.id, updates)

    @router.delete(
        "/me",
        status_code=204,
        description=(
            "Delete your own account. Needs proof of presence: either "
            "`current_password` in the body, or a session whose credentials were "
            "checked within `REAUTH_MAX_AGE_SECONDS`. Answers 403 otherwise."
        ),
    )
    async def delete_me_route(
        request: Request,
        user: CurrentUser,
        payload: TokenPayload = Depends(current_token_payload),
        fullauth: "FullAuth" = Depends(get_fullauth),
        data: DeleteAccountRequest | None = Body(None),
    ) -> None:
        # The password check below is an oracle for whoever holds the token, and
        # a correct guess deletes the account. Meter it like a sign-in.
        await fullauth.enforce_rate_limit(request, "reauth")

        # Deleting an account cannot be undone, so a token someone found is not
        # enough on its own.
        try:
            await verify_recent_auth(
                payload,
                hashed_password=await fullauth.adapter.get_hashed_password(user.id),
                current_password=data.current_password if data else None,
                max_age_seconds=fullauth.config.REAUTH_MAX_AGE_SECONDS,
                max_password_length=fullauth.config.PASSWORD_MAX_LENGTH,
            )
        except AuthenticationError as e:
            raise HTTPException(status_code=403, detail=str(e)) from e

        await fullauth.adapter.revoke_all_user_refresh_tokens(user.id)
        await fullauth.adapter.delete_user(user.id)
        logger.warning("Account deleted: user_id=%s, email=%s", user.id, user.email)

    @router.post(
        "/change-password",
        status_code=200,
        response_model=message_response_schema,
        description=(
            "Change password. `current_password` is required when the user already "
            "has one. An account without a stored password is setting its first, "
            "which needs a session whose credentials were checked within "
            "`REAUTH_MAX_AGE_SECONDS` instead."
        ),
    )
    async def change_password_route(
        data: ChangePasswordRequest,
        request: Request,
        user: CurrentUser,
        payload: TokenPayload = Depends(current_token_payload),
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        # `current_password` is the same oracle as above.
        await fullauth.enforce_rate_limit(request, "reauth")

        # Setting the first password on an OAuth-only or passkey-only account has
        # no current password to check, and it creates a new way in, so presence
        # has to be proved some other way.
        if await fullauth.adapter.get_hashed_password(user.id) is None:
            try:
                await verify_recent_auth(
                    payload,
                    hashed_password=None,
                    max_age_seconds=fullauth.config.REAUTH_MAX_AGE_SECONDS,
                )
            except AuthenticationError as e:
                raise HTTPException(status_code=403, detail=str(e)) from e

        try:
            await change_password(
                adapter=fullauth.adapter,
                user_id=user.id,
                new_password=data.new_password,
                current_password=data.current_password,
                hash_algorithm=fullauth.config.PASSWORD_HASH_ALGORITHM,
                password_validator=fullauth.password_validator,
                token_engine=fullauth.token_engine,
            )
        except AuthenticationError:
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        except InvalidPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))

        await fullauth.hooks.emit("after_password_change", user=user)
        return message_response_schema(detail="Password changed successfully.")

    return router
