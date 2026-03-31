"""fastapi-fullauth: Production-grade auth for FastAPI."""

__version__ = "0.1.0"

from fastapi_fullauth.config import FullAuthConfig
from fastapi_fullauth.fullauth import FullAuth
from fastapi_fullauth.utils import create_superuser, generate_secret_key
from fastapi_fullauth.validators import PasswordValidator

__all__ = [
    "FullAuth",
    "FullAuthConfig",
    "PasswordValidator",
    "create_superuser",
    "generate_secret_key",
]
