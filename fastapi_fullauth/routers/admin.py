import logging
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from fastapi_fullauth.adapters.base import PermissionAdapterMixin, RoleAdapterMixin
from fastapi_fullauth.dependencies.current_user import SuperUser, get_fullauth
from fastapi_fullauth.routers._schemas import (
    MessageResponse,
    PermissionAssignment,
    build_role_assignment_model,
)

logger = logging.getLogger("fastapi_fullauth.routers")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def _require_permissions(fullauth: "FullAuth") -> None:
    """The admin router mounts on role support alone, so the permission routes
    can exist against an adapter with no permission models. Say so, rather than
    letting the adapter's RuntimeError surface as a 500."""
    if not fullauth.adapter.supports_feature("permission"):
        raise HTTPException(status_code=501, detail="Adapter does not support permissions")


def create_admin_router(user_id_type: Any = UUID) -> APIRouter:
    router = APIRouter()
    RoleAssignment = build_role_assignment_model(user_id_type)  # noqa: N806

    @router.post(
        "/admin/assign-role",
        status_code=200,
        response_model=MessageResponse,
        description="Assign a role to a user. Superuser only.",
    )
    async def assign_role_route(
        data: RoleAssignment,  # type: ignore[valid-type]
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        # RoleAssignment is built dynamically, so read its fields via model_dump().
        fields = cast("BaseModel", data).model_dump()
        user_id, role = fields["user_id"], fields["role"]
        target = await fullauth.adapter.get_user_by_id(user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        await cast("RoleAdapterMixin", fullauth.adapter).assign_role(user_id, role)
        logger.info("Role assigned: target=%s, role=%s, by=%s", user_id, role, caller.id)
        return MessageResponse(detail=f"Role '{role}' assigned to user {user_id}.")

    @router.post(
        "/admin/remove-role",
        status_code=200,
        response_model=MessageResponse,
        description="Remove a role from a user. Superuser only.",
    )
    async def remove_role_route(
        data: RoleAssignment,  # type: ignore[valid-type]
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        fields = cast("BaseModel", data).model_dump()
        user_id, role = fields["user_id"], fields["role"]
        await cast("RoleAdapterMixin", fullauth.adapter).remove_role(user_id, role)
        logger.info("Role removed: target=%s, role=%s, by=%s", user_id, role, caller.id)
        return MessageResponse(detail=f"Role '{role}' removed from user {user_id}.")

    @router.post(
        "/admin/assign-permission",
        status_code=200,
        response_model=MessageResponse,
        description="Assign a permission to a role. Superuser only.",
    )
    async def assign_permission_route(
        data: PermissionAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        _require_permissions(fullauth)
        await cast("PermissionAdapterMixin", fullauth.adapter).assign_permission_to_role(
            data.role, data.permission
        )
        logger.info(
            "Permission assigned: role=%s, permission=%s, by=%s",
            data.role,
            data.permission,
            caller.id,
        )
        return MessageResponse(
            detail=f"Permission '{data.permission}' assigned to role '{data.role}'.",
        )

    @router.post(
        "/admin/remove-permission",
        status_code=200,
        response_model=MessageResponse,
        description="Remove a permission from a role. Superuser only.",
    )
    async def remove_permission_route(
        data: PermissionAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> MessageResponse:
        _require_permissions(fullauth)
        await cast("PermissionAdapterMixin", fullauth.adapter).remove_permission_from_role(
            data.role, data.permission
        )
        logger.info(
            "Permission removed: role=%s, permission=%s, by=%s",
            data.role,
            data.permission,
            caller.id,
        )
        return MessageResponse(
            detail=f"Permission '{data.permission}' removed from role '{data.role}'.",
        )

    @router.get(
        "/admin/role-permissions/{role_name}",
        status_code=200,
        description="List permissions for a role. Superuser only.",
    )
    async def list_role_permissions_route(
        role_name: str,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(get_fullauth),
    ) -> list[str]:
        _require_permissions(fullauth)
        return await cast("PermissionAdapterMixin", fullauth.adapter).get_role_permissions(
            role_name
        )

    return router
