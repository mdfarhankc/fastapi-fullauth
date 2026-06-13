from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr

from fastapi_fullauth.types import TokenPair, UserSchema


class LoginResponse(TokenPair):
    user: UserSchema | None = None


def build_login_model(login_field: str) -> type[BaseModel]:
    from pydantic import create_model

    fields: dict[str, Any] = {login_field: (str, ...), "password": (str, ...)}
    model: type[BaseModel] = create_model("LoginRequest", **fields)
    return model


def build_login_response_model(
    user_schema: type[UserSchema] = UserSchema,
    base: type[LoginResponse] = LoginResponse,
) -> type[LoginResponse]:
    """Build the login response model, typing the ``user`` field to ``user_schema``.

    Pass ``base`` to start from a custom ``LoginResponse`` subclass (e.g. one that
    adds extra top-level fields to the token response).
    """
    from pydantic import create_model

    model: type[LoginResponse] = create_model(
        "LoginResponse",
        __base__=base,
        user=(user_schema | None, None),
    )
    return model


def build_profile_update_model(user_schema: type[UserSchema] = UserSchema) -> type[BaseModel]:
    """Build a PATCH body model from the schema's non-protected fields.

    Every field is optional so partial updates work, and the model documents the
    updatable fields in the OpenAPI schema. ``extra="allow"`` keeps unrecognized
    keys so ``validate_profile_updates`` can still reject them with a 422 rather
    than silently dropping them at parse time.
    """
    from pydantic import create_model

    protected = user_schema.PROTECTED_FIELDS
    fields: dict[str, Any] = {}
    for name, info in user_schema.model_fields.items():
        if name in protected:
            continue
        annotation: Any = info.annotation
        fields[name] = (annotation | None, None)
    model: type[BaseModel] = create_model(
        "ProfileUpdate",
        __config__=ConfigDict(extra="allow"),
        **fields,
    )
    return model


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class VerifyEmailRequest(BaseModel):
    token: str


class RefreshRequest(BaseModel):
    # Optional so a cookie-transport client can POST /refresh with an empty body;
    # the route reads the token from the backend cookie when it isn't supplied.
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    new_password: str
    current_password: str | None = None


class RoleAssignment(BaseModel):
    user_id: UUID
    role: str


class PermissionAssignment(BaseModel):
    role: str
    permission: str


class MessageResponse(BaseModel):
    detail: str
