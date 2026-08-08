from fastapi import HTTPException, status

__all__ = [
    "CREDENTIALS_EXCEPTION",
    "FORBIDDEN_EXCEPTION",
    "OAUTH_ERROR_EXCEPTION",
    "USER_EXISTS_EXCEPTION",
    "AccountLockedError",
    "AuthenticationError",
    "AuthorizationError",
    "FullAuthError",
    "InvalidPasswordError",
    "NoValidFieldsError",
    "OAuthAccountAlreadyLinkedError",
    "OAuthError",
    "OAuthProviderError",
    "RefreshTokenReuseError",
    "TokenBlacklistedError",
    "TokenError",
    "TokenExpiredError",
    "UnknownFieldsError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
]


class FullAuthError(Exception):
    """Base class for every exception this library raises."""


class AuthenticationError(FullAuthError):
    """Credentials are wrong, the user is unknown, or the account is inactive."""


class AuthorizationError(FullAuthError):
    """The authenticated user lacks the required role or permission."""


class TokenError(FullAuthError):
    """A token failed validation (bad signature, wrong type or purpose)."""


class UserAlreadyExistsError(FullAuthError):
    """Registration hit an existing account for the same login field."""


class UserNotFoundError(FullAuthError):
    """No user matches the given id or lookup field."""


class InvalidPasswordError(FullAuthError):
    """The password fails the configured validation rules or algorithm limits."""


class AccountLockedError(FullAuthError):
    """Login blocked because the lockout threshold was reached."""


class TokenBlacklistedError(TokenError):
    """The token was revoked (logout or explicit blacklisting)."""


class TokenExpiredError(TokenError):
    """The token's ``exp`` claim is in the past."""


class RefreshTokenReuseError(TokenError):
    """An already-rotated refresh token was presented; its family is revoked."""


class OAuthError(FullAuthError):
    """Base class for OAuth flow failures."""


class OAuthProviderError(OAuthError):
    """The identity provider rejected a request or answered unusably."""


class OAuthAccountAlreadyLinkedError(OAuthError):
    """The provider identity is already linked to a different user."""


class NoValidFieldsError(FullAuthError):
    """A profile update contained no updatable fields."""


class UnknownFieldsError(FullAuthError):
    """A profile update named fields that don't exist on the user schema."""

    def __init__(self, fields: set[str]) -> None:
        self.fields = fields
        super().__init__(f"Unknown fields: {', '.join(sorted(fields))}")


CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

FORBIDDEN_EXCEPTION = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Not enough permissions",
)

USER_EXISTS_EXCEPTION = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="A user with this email already exists",
)

OAUTH_ERROR_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="OAuth authentication failed",
)
