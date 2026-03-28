from fastapi import Depends, FastAPI

from fastapi_fullauth import FullAuth, FullAuthConfig
from fastapi_fullauth.adapters.memory import InMemoryAdapter
from fastapi_fullauth.dependencies import current_user, require_role

app = FastAPI(title="FullAuth Demo")

fullauth = FullAuth(
    config=FullAuthConfig(SECRET_KEY="change-me-in-production"),
    adapter=InMemoryAdapter(),
)
fullauth.init_app(app)


@app.get("/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/admin")
async def admin_only(user=Depends(require_role("admin"))):
    return {"msg": "welcome admin", "user": user}
