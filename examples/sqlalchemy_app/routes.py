from fastapi import APIRouter, Depends

from fastapi_fullauth.dependencies import current_user, require_role

router = APIRouter(prefix="/api/v1")


@router.get("/dashboard")
async def dashboard(user=Depends(current_user)):
    return {"msg": "welcome", "user": user}


@router.get("/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "admin area", "user": user}
