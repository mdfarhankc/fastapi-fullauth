import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException

from fastapi_fullauth.dependencies.current_user import SuperUser, _get_fullauth
from fastapi_fullauth.router._models import MessageResponse, PermissionAssignment, RoleAssignment

logger = logging.getLogger("fastapi_fullauth.router")

if TYPE_CHECKING:
    from fastapi_fullauth.fullauth import FullAuth


def create_admin_router() -> APIRouter:
    router = APIRouter()

    @router.post(
        "/admin/assign-role",
        status_code=200,
        response_model=MessageResponse,
        description="Assign a role to a user. Superuser only.",
    )
    async def assign_role_route(
        data: RoleAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        target = await fullauth.adapter.get_user_by_id(data.user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        await fullauth.adapter.assign_role(data.user_id, data.role)
        logger.info("Role assigned: target=%s, role=%s, by=%s", data.user_id, data.role, caller.id)
        return MessageResponse(detail=f"Role '{data.role}' assigned to user {data.user_id}.")

    @router.post(
        "/admin/remove-role",
        status_code=200,
        response_model=MessageResponse,
        description="Remove a role from a user. Superuser only.",
    )
    async def remove_role_route(
        data: RoleAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        await fullauth.adapter.remove_role(data.user_id, data.role)
        logger.info("Role removed: target=%s, role=%s, by=%s", data.user_id, data.role, caller.id)
        return MessageResponse(detail=f"Role '{data.role}' removed from user {data.user_id}.")

    @router.post(
        "/admin/assign-permission",
        status_code=200,
        response_model=MessageResponse,
        description="Assign a permission to a role. Superuser only.",
    )
    async def assign_permission_route(
        data: PermissionAssignment,
        caller: SuperUser,
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        await fullauth.adapter.assign_permission_to_role(data.role, data.permission)
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
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> MessageResponse:
        await fullauth.adapter.remove_permission_from_role(data.role, data.permission)
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
        fullauth: "FullAuth" = Depends(_get_fullauth),
    ) -> list[str]:
        return await fullauth.adapter.get_role_permissions(role_name)

    return router
