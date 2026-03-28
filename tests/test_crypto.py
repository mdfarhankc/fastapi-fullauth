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
