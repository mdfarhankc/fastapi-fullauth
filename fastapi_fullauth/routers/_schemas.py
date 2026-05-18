from typing import Any
from uuid import UUID

from pydantic import BaseModel, EmailStr

from fastapi_fullauth.types import TokenPair, UserSchema


class LoginResponse(TokenPair):
    user: UserSchema | None = None


def build_login_model(login_field: str) -> type[BaseModel]:
    from pydantic import create_model

    fields: dict[str, Any] = {login_field: (str, ...), "password": (str, ...)}
    model: type[BaseModel] = create_model("LoginRequest", **fields)
    return model


def build_login_response_model(user_schema: type[UserSchema] = UserSchema) -> type[LoginResponse]:
    from pydantic import create_model

    model: type[LoginResponse] = create_model(
        "LoginResponse",
        __base__=LoginResponse,
        user=(user_schema | None, None),
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
    refresh_token: str


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
