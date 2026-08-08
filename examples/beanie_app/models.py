from fastapi_fullauth.models.beanie import (
    RefreshTokenDocument,
    RoleDocument,
    UserDocument,
)


class Role(RoleDocument):
    pass


class RefreshToken(RefreshTokenDocument):
    pass


class User(UserDocument):
    # Roles are an embedded array on the user document (no join collection), so
    # only role_model is passed to the adapter. Add your own fields freely.
    display_name: str = ""
    phone: str = ""


# Register every document with init_beanie() at startup (see main.py).
DOCUMENT_MODELS = [User, RefreshToken, Role]
