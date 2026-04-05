from typing import Annotated

from fastapi import Depends

from fastapi_fullauth.dependencies.current_user import (
    current_active_verified_user,
    current_user,
)
from fastapi_fullauth.dependencies.require_role import require_permission, require_role
from fastapi_fullauth.types import UserSchema

CurrentUser = Annotated[UserSchema, Depends(current_user)]
VerifiedUser = Annotated[UserSchema, Depends(current_active_verified_user)]

__all__ = [
    "CurrentUser",
    "VerifiedUser",
    "current_active_verified_user",
    "current_user",
    "require_permission",
    "require_role",
]
