from uuid import UUID

import uuid_utils


def uuid7() -> UUID:
    """A time-ordered UUIDv7 as a stdlib ``uuid.UUID``.

    Tortoise's ``UUIDField`` is typed against ``uuid.UUID``; ``uuid_utils.uuid7``
    returns its own UUID type, so convert via ``bytes`` to keep the ordering.
    """
    return UUID(bytes=uuid_utils.uuid7().bytes)
