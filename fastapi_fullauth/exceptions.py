from fastapi import HTTPException, status


class FullAuthError(Exception):
    """Base exception for all fastapi-fullauth errors."""


class AuthenticationError(FullAuthError):
    """Raised when authentication fails."""


class AuthorizationError(FullAuthError):
    """Raised when authorization fails."""


class TokenError(FullAuthError):
    """Raised for token-related errors (expired, invalid, blacklisted)."""


class UserAlreadyExistsError(FullAuthError):
    """Raised when trying to create a user that already exists."""


class UserNotFoundError(FullAuthError):
    """Raised when a user cannot be found."""


class InvalidPasswordError(FullAuthError):
    """Raised when password validation fails."""


class AccountLockedError(FullAuthError):
    """Raised when account is locked due to too many failed attempts."""


class TokenBlacklistedError(TokenError):
    """Raised when a blacklisted token is used."""


class TokenExpiredError(TokenError):
    """Raised when an expired token is used."""


class RefreshTokenReuseError(TokenError):
    """Raised when a refresh token is reused (possible theft)."""


# --- HTTP exceptions (ready to raise in routes) ---

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
