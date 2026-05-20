import warnings
from typing import Any, Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class FullAuthConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FULLAUTH_",
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Single source-of-truth defaults. Each per-feature setting below
    # inherits these when not explicitly set.
    BACKEND: Literal["memory", "redis"] = "memory"
    ORIGINS: list[str] = []

    SECRET_KEY: str | None = None
    ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    REFRESH_TOKEN_ROTATION: bool = True
    JWT_LEEWAY_SECONDS: int = 30

    PASSWORD_RESET_EXPIRE_MINUTES: int = 15
    EMAIL_VERIFY_EXPIRE_MINUTES: int = 1440

    PASSWORD_HASH_ALGORITHM: Literal["argon2id", "bcrypt"] = "argon2id"
    PASSWORD_MIN_LENGTH: int = 8

    LOGIN_FIELD: str = "email"
    # When True, login runs a dummy password verify on unknown-user / no-password
    # paths so responses take roughly the same time as a real wrong-password attempt.
    # Defaults off = adds ~argon2 hashing time to every failed lookup.
    PREVENT_LOGIN_TIMING_ATTACKS: bool = False

    LOCKOUT_ENABLED: bool = True
    LOCKOUT_BACKEND: Literal["memory", "redis"] = "memory"
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    RATE_LIMIT_BACKEND: Literal["memory", "redis"] = "memory"
    TRUSTED_PROXY_HEADERS: list[str] = []

    AUTH_RATE_LIMIT_ENABLED: bool = True
    AUTH_RATE_LIMIT_LOGIN: int = 5
    AUTH_RATE_LIMIT_REGISTER: int = 3
    AUTH_RATE_LIMIT_PASSWORD_RESET: int = 3
    AUTH_RATE_LIMIT_PASSKEY_AUTH: int = 10
    AUTH_RATE_LIMIT_REFRESH: int = 30
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60

    REDIS_URL: str | None = None

    BLACKLIST_ENABLED: bool = True
    BLACKLIST_BACKEND: Literal["memory", "redis"] = "memory"

    CSRF_SECRET: str | None = None

    COOKIE_NAME: str = "fullauth_access"
    COOKIE_SECURE: bool = True
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    COOKIE_DOMAIN: str | None = None

    OAUTH_STATE_EXPIRE_SECONDS: int = 300
    OAUTH_AUTO_LINK_BY_EMAIL: bool = True

    PREVENT_REGISTRATION_ENUMERATION: bool = False

    PASSKEY_ENABLED: bool = False
    PASSKEY_RP_ID: str | None = None
    PASSKEY_RP_NAME: str | None = None
    PASSKEY_ORIGINS: list[str] = []
    PASSKEY_CHALLENGE_BACKEND: Literal["memory", "redis"] = "memory"
    PASSKEY_CHALLENGE_TTL: int = 60
    PASSKEY_REQUIRE_USER_VERIFICATION: bool = True

    API_PREFIX: str = "/api/v1"
    AUTH_ROUTER_PREFIX: str = "/auth"
    ROUTER_TAGS: list[str] = ["Auth"]

    @model_validator(mode="before")
    @classmethod
    def _apply_global_defaults(cls, values: Any) -> Any:
        """Propagate ``BACKEND`` → individual ``*_BACKEND`` settings and
        ``ORIGINS`` → ``PASSKEY_ORIGINS`` when the specific setting isn't set.
        ``setdefault`` means explicit per-feature overrides win.
        """
        if not isinstance(values, dict):
            return values

        backend = values.get("BACKEND")
        if backend:
            for key in (
                "BLACKLIST_BACKEND",
                "LOCKOUT_BACKEND",
                "RATE_LIMIT_BACKEND",
                "PASSKEY_CHALLENGE_BACKEND",
            ):
                values.setdefault(key, backend)

        origins = values.get("ORIGINS")
        if origins:
            values.setdefault("PASSKEY_ORIGINS", origins)

        return values

    @model_validator(mode="after")
    def _validate_redis_url(self) -> "FullAuthConfig":
        """Fail-fast at config construction if any enabled feature uses redis
        without REDIS_URL set."""
        needs_redis: list[str] = []
        if self.BLACKLIST_ENABLED and self.BLACKLIST_BACKEND == "redis":
            needs_redis.append("BLACKLIST_BACKEND")
        if self.LOCKOUT_ENABLED and self.LOCKOUT_BACKEND == "redis":
            needs_redis.append("LOCKOUT_BACKEND")
        if self.AUTH_RATE_LIMIT_ENABLED and self.RATE_LIMIT_BACKEND == "redis":
            needs_redis.append("RATE_LIMIT_BACKEND")
        if self.PASSKEY_ENABLED and self.PASSKEY_CHALLENGE_BACKEND == "redis":
            needs_redis.append("PASSKEY_CHALLENGE_BACKEND")

        if needs_redis and not self.REDIS_URL:
            raise ValueError(f"REDIS_URL must be set when {', '.join(needs_redis)} use 'redis'.")
        return self

    @model_validator(mode="after")
    def _ensure_secret_key(self) -> "FullAuthConfig":
        if self.SECRET_KEY is None:
            from fastapi_fullauth.utils import generate_secret_key

            object.__setattr__(self, "SECRET_KEY", generate_secret_key())
            warnings.warn(
                "FULLAUTH_SECRET_KEY is not set. A random key has been generated. "
                "Tokens will be invalidated on restart. "
                "Set FULLAUTH_SECRET_KEY for production.",
                UserWarning,
                stacklevel=2,
            )
        elif len(self.SECRET_KEY) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters. "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(64))'"
            )
        return self

    @model_validator(mode="after")
    def _validate_passkey_config(self) -> "FullAuthConfig":
        if not self.PASSKEY_ENABLED:
            return self

        if not self.PASSKEY_RP_ID:
            raise ValueError("PASSKEY_RP_ID is required when PASSKEY_ENABLED=True")
        if "://" in self.PASSKEY_RP_ID or "/" in self.PASSKEY_RP_ID:
            raise ValueError(
                f"PASSKEY_RP_ID must be a bare domain, got {self.PASSKEY_RP_ID!r}. "
                "No scheme, no path (e.g. 'example.com', not 'https://example.com')."
            )

        if not self.PASSKEY_ORIGINS:
            raise ValueError("PASSKEY_ORIGINS is required when PASSKEY_ENABLED=True")
        for origin in self.PASSKEY_ORIGINS:
            if "://" not in origin or origin.count("/") > 2:
                raise ValueError(
                    f"PASSKEY_ORIGINS entry {origin!r} must be a full origin "
                    "(scheme://host[:port], no path)."
                )

        return self
