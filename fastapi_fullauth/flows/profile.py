from typing import Any

from fastapi_fullauth.exceptions import NoValidFieldsError, UnknownFieldsError
from fastapi_fullauth.types import UserSchema


def validate_profile_updates(
    data: dict[str, Any],
    user_schema: type[UserSchema],
    current: UserSchema | None = None,
) -> dict[str, Any]:
    """Filter protected fields and validate that remaining fields are known.

    When ``current`` is given, the updates are also merged over it and validated
    against ``user_schema``, so field constraints, custom validators, and
    nullability apply exactly as they do for the stored user. The returned values
    are the validated ones.

    Raises NoValidFieldsError if all fields are protected.
    Raises UnknownFieldsError if any field is not on the schema.
    Raises pydantic.ValidationError if the merged user is invalid.
    """
    protected = user_schema.PROTECTED_FIELDS
    updates = {k: v for k, v in data.items() if k not in protected}
    if not updates:
        raise NoValidFieldsError("No valid fields to update")

    allowed = set(user_schema.model_fields.keys()) - protected
    unknown = set(updates.keys()) - allowed
    if unknown:
        raise UnknownFieldsError(unknown)

    if current is None:
        return updates

    validated = user_schema.model_validate({**current.model_dump(), **updates})
    return validated.model_dump(include=set(updates))
