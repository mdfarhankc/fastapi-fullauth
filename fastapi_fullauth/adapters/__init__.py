"""Adapters — the persistence seam between FullAuth and your database.

Two built-ins ship: ``SQLAlchemyAdapter`` and ``SQLModelAdapter``. Each is
imported only when the matching optional dependency is installed, so a
missing extra (e.g. you installed ``[sqlalchemy]`` only) leaves the other
adapter unbound rather than breaking import. Any other ``ImportError``
inside the adapter module propagates — masking those would hide real bugs.

    from fastapi_fullauth.adapters import SQLAlchemyAdapter
    # or
    from fastapi_fullauth.adapters import SQLModelAdapter
"""

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
)

__all__ = [
    "AbstractUserAdapter",
    "OAuthAdapterMixin",
    "PasskeyAdapterMixin",
    "PermissionAdapterMixin",
    "RoleAdapterMixin",
]

try:
    import sqlalchemy  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.adapters.sqlalchemy import SQLAlchemyAdapter  # noqa: F401

    __all__.append("SQLAlchemyAdapter")

try:
    import sqlmodel  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.adapters.sqlmodel import SQLModelAdapter  # noqa: F401

    __all__.append("SQLModelAdapter")
