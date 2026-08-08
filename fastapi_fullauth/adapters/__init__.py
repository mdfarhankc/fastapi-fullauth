"""Adapters = the persistence seam between FullAuth and your database.

Four built-ins ship: ``SQLAlchemyAdapter``, ``SQLModelAdapter``,
``TortoiseAdapter``, and ``BeanieAdapter`` (MongoDB). Each is imported only when
the matching optional dependency is installed, so a missing extra (e.g. you
installed ``[sqlalchemy]`` only) leaves the others unbound rather than breaking
import. Any other ``ImportError`` inside the adapter module propagates = masking
those would hide real bugs.

    from fastapi_fullauth.adapters import SQLAlchemyAdapter
    # or
    from fastapi_fullauth.adapters import SQLModelAdapter
    # or
    from fastapi_fullauth.adapters import TortoiseAdapter
    # or
    from fastapi_fullauth.adapters import BeanieAdapter
"""

from fastapi_fullauth.adapters.base import (
    AbstractUserAdapter,
    AdapterFeature,
    OAuthAdapterMixin,
    PasskeyAdapterMixin,
    PermissionAdapterMixin,
    RoleAdapterMixin,
    SessionAdapterMixin,
)

__all__ = [
    "AbstractUserAdapter",
    "AdapterFeature",
    "OAuthAdapterMixin",
    "PasskeyAdapterMixin",
    "PermissionAdapterMixin",
    "RoleAdapterMixin",
    "SessionAdapterMixin",
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

try:
    import tortoise  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.adapters.tortoise import TortoiseAdapter  # noqa: F401

    __all__.append("TortoiseAdapter")

try:
    import beanie  # noqa: F401
except ImportError:
    pass
else:
    from fastapi_fullauth.adapters.beanie import BeanieAdapter  # noqa: F401

    __all__.append("BeanieAdapter")
