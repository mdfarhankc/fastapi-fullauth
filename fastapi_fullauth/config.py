from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings


class FullAuthConfig(BaseSettings):
    model_config = {"env_prefix": "FULLAUTH_"}

    # --- Security ---
    SECRET_KEY: str
    ALGORITHM: str = "HS256"

    # --- Tokens ---
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    REFRESH_TOKEN_ROTATION: bool = True

    # --- Password ---
    PASSWORD_HASH_ALGORITHM: Literal["argon2id", "bcrypt"] = "argon2id"
    PASSWORD_MIN_LENGTH: int = 8

    # --- Brute-force protection ---
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # --- Rate limiting ---
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_BACKEND: Literal["memory", "redis"] = "memory"

    # --- Redis ---
    REDIS_URL: str | None = None

    # --- Token blacklist ---
    BLACKLIST_ENABLED: bool = True
    BLACKLIST_BACKEND: Literal["memory", "redis"] = "memory"

    # --- CORS / Security headers ---
    INJECT_SECURITY_HEADERS: bool = True

    # --- CSRF ---
    CSRF_ENABLED: bool = False
    CSRF_SECRET: str | None = None

    # --- Cookie backend ---
    COOKIE_NAME: str = "fullauth_access"
    COOKIE_SECURE: bool = True
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    COOKIE_DOMAIN: str | None = None

    # --- Paths ---
    API_PREFIX: str = "/api/v1"
    AUTH_ROUTER_PREFIX: str = "/auth"
    ROUTER_TAGS: list[str] = ["Auth"]
