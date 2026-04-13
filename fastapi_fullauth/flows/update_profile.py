from typing import Any

from fastapi_fullauth.exceptions import NoValidFieldsError, UnknownFieldsError
from fastapi_fullauth.types import UserSchema


def validate_profile_updates(
    data: dict[str, Any],
    user_schema: type[UserSchema],
) -> dict[str, Any]:
    """Filter protected fields and validate that remaining fields are known.

    Returns the cleaned update dict.
    Raises NoValidFieldsError if all fields are protected.
    Raises UnknownFieldsError if any field is not on the schema.
    """
    protected = user_schema.PROTECTED_FIELDS
    updates = {k: v for k, v in data.items() if k not in protected}
    if not updates:
        raise NoValidFieldsError("No valid fields to update")

    allowed = set(user_schema.model_fields.keys()) - protected
    unknown = set(updates.keys()) - allowed
    if unknown:
        raise UnknownFieldsError(unknown)

    return updates
