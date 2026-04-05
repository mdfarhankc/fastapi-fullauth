from fastapi import HTTPException, status


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
