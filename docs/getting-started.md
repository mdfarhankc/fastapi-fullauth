# Getting Started

This guide walks through setting up fastapi-fullauth from scratch.

## Installation

```bash
pip install fastapi-fullauth[sqlmodel]
```

## 1. Define your user model

```python
# models.py
from sqlmodel import Field, Relationship
from fastapi_fullauth.adapters.sqlmodel import (
    UserBase, Role, UserRoleLink, RefreshTokenRecord,
)

class User(UserBase, table=True):
    __tablename__ = "fullauth_users"

    display_name: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=20)

    roles: list[Role] = Relationship(link_model=UserRoleLink)
    refresh_tokens: list[RefreshTokenRecord] = Relationship()
```

`UserBase` provides `id`, `email`, `hashed_password`, `is_active`, `is_verified`, `is_superuser`, and `created_at`. Add any extra fields you need.

!!! note
    Registration and response schemas are **auto-derived** from your model. `display_name` and `phone` will appear in the register endpoint and user responses automatically.

## 2. Set up the database

```python
# config.py
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DATABASE_URL = "sqlite+aiosqlite:///app.db"
engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)
```

## 3. Configure FullAuth

```python
# auth.py
from fastapi_fullauth import FullAuth
from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter

from .config import session_maker
from .models import User

fullauth = FullAuth(
    secret_key="your-secret-key-at-least-32-bytes",
    adapter=SQLModelAdapter(session_maker=session_maker, user_model=User),
)
```

!!! tip
    Omit `secret_key` during development and a random one is generated automatically. Tokens won't survive restarts, but it's convenient for dev.

## 4. Wire it into FastAPI

```python
# main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlmodel import SQLModel

from .auth import fullauth
from .config import engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await engine.dispose()

app = FastAPI(lifespan=lifespan)
fullauth.init_app(app)
```

That's it. Start the server and you have a full auth system:

```bash
uvicorn main:app --reload
```

## 5. Try it out

**Register:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

**Login:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Get current user:**

```bash
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer eyJ..."
```

## 6. Add protected routes

```python
from fastapi_fullauth.dependencies import CurrentUser, VerifiedUser, require_role

@app.get("/profile")
async def profile(user: CurrentUser):
    return user

@app.get("/dashboard")
async def dashboard(user: VerifiedUser):
    return {"email": user.email}

@app.get("/admin")
async def admin(user=Depends(require_role("admin"))):
    return {"msg": "admin area"}
```

See [Protected Routes](auth/dependencies.md) for all dependency types.

## Next steps

- [Configuration](configuration.md) — all config options
- [OAuth2 Social Login](oauth.md) — add Google/GitHub login
- [Event Hooks](auth/hooks.md) — send emails, log events
- [Rate Limiting](security/rate-limiting.md) — protect your endpoints
