from fastapi import HTTPException, status

__all__ = [
    "ACCOUNT_LOCKED_EXCEPTION",
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
    pass


class AuthenticationError(FullAuthError):
    pass


class AuthorizationError(FullAuthError):
    pass


class TokenError(FullAuthError):
    pass


class UserAlreadyExistsError(FullAuthError):
    pass


class UserNotFoundError(FullAuthError):
    pass


class InvalidPasswordError(FullAuthError):
    pass


class AccountLockedError(FullAuthError):
    pass


class TokenBlacklistedError(TokenError):
    pass


class TokenExpiredError(TokenError):
    pass


class RefreshTokenReuseError(TokenError):
    pass


class OAuthError(FullAuthError):
    pass


class OAuthProviderError(OAuthError):
    pass


class OAuthAccountAlreadyLinkedError(OAuthError):
    pass


class NoValidFieldsError(FullAuthError):
    pass


class UnknownFieldsError(FullAuthError):
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

ACCOUNT_LOCKED_EXCEPTION = HTTPException(
    status_code=status.HTTP_423_LOCKED,
    detail="Account is temporarily locked due to too many failed login attempts",
)

OAUTH_ERROR_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="OAuth authentication failed",
)
