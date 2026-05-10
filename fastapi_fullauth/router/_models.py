from uuid import UUID

from pydantic import BaseModel, EmailStr

from fastapi_fullauth.types import TokenPair, UserSchema


class LoginResponse(TokenPair):
    user: UserSchema | None = None


def build_login_model(login_field: str) -> type[BaseModel]:
    from pydantic import create_model

    return create_model("LoginRequest", **{login_field: (str, ...), "password": (str, ...)})


def build_login_response_model(user_schema: type[UserSchema] = UserSchema) -> type[LoginResponse]:
    from pydantic import create_model

    return create_model(
        "LoginResponse",
        __base__=LoginResponse,
        user=(user_schema | None, None),
    )


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
    current_password: str
    new_password: str


class SetPasswordRequest(BaseModel):
    new_password: str


class RoleAssignment(BaseModel):
    user_id: UUID
    role: str


class PermissionAssignment(BaseModel):
    role: str
    permission: str


class MessageResponse(BaseModel):
    detail: str
