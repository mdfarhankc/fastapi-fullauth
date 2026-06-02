import pytest

from fastapi_fullauth.core.crypto import hash_password, password_needs_rehash, verify_password


def test_hash_and_verify():
    hashed = hash_password("mypassword")
    assert hashed != "mypassword"
    assert verify_password("mypassword", hashed)


def test_wrong_password():
    hashed = hash_password("mypassword")
    assert not verify_password("wrongpassword", hashed)


def test_different_hashes():
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2  # salted


def test_needs_rehash():
    hashed = hash_password("test")
    assert not password_needs_rehash(hashed)


def test_bcrypt_legacy_prefixes_verify():
    pytest.importorskip("bcrypt")
    hashed = hash_password("legacy-pw", algorithm="bcrypt")  # produces $2b$
    for prefix in ("$2a$", "$2y$"):
        legacy = prefix + hashed[4:]
        assert verify_password("legacy-pw", legacy)
        assert not verify_password("wrong-pw", legacy)
        assert not password_needs_rehash(legacy, algorithm="bcrypt")
        assert password_needs_rehash(legacy, algorithm="argon2id")
