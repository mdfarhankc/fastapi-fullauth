"""Tests for the cookie auth backend."""

import pytest
from fastapi import Response

from fastapi_fullauth import FullAuthConfig
from fastapi_fullauth.backends.cookie import CookieBackend


def _set_cookie_headers(response: Response) -> list[str]:
    return [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]


@pytest.mark.asyncio
async def test_delete_token_matches_write_token_attributes():
    """Both set-cookies (write and delete) must share secure/samesite/path/domain
    so browsers actually honour the deletion."""
    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
        COOKIE_SECURE=True,
        COOKIE_HTTPONLY=True,
        COOKIE_SAMESITE="none",
        COOKIE_DOMAIN="example.com",
    )
    backend = CookieBackend(config)

    write = Response()
    await backend.write_token(write, "some.jwt.token")
    delete = Response()
    await backend.delete_token(delete)

    write_header = _set_cookie_headers(write)[0].lower()
    delete_header = _set_cookie_headers(delete)[0].lower()

    for marker in ("secure", "samesite=none", "httponly", "domain=example.com", "path=/"):
        assert marker in write_header, f"write missing {marker}: {write_header}"
        assert marker in delete_header, f"delete missing {marker}: {delete_header}"

    # deletion is marked by max-age=0
    assert "max-age=0" in delete_header


@pytest.mark.asyncio
async def test_delete_token_with_default_samesite():
    config = FullAuthConfig(
        SECRET_KEY="test-secret-key-that-is-long-enough-32b",
    )
    backend = CookieBackend(config)

    response = Response()
    await backend.delete_token(response)
    header = _set_cookie_headers(response)[0].lower()

    assert "samesite=lax" in header
    assert "secure" in header
    assert "max-age=0" in header
