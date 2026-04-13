from fastapi_fullauth.router.admin import create_admin_router
from fastapi_fullauth.router.auth import create_auth_router
from fastapi_fullauth.router.profile import create_profile_router
from fastapi_fullauth.router.verify import create_verify_router

__all__ = [
    "create_admin_router",
    "create_auth_router",
    "create_profile_router",
    "create_verify_router",
]
