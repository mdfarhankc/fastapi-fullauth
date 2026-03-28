import time
from unittest.mock import patch

from fastapi_fullauth.protection.lockout import LockoutManager


def test_not_locked_initially():
    mgr = LockoutManager(max_attempts=3, lockout_seconds=60)
    assert not mgr.is_locked("user@test.com")


def test_locks_after_max_attempts():
    mgr = LockoutManager(max_attempts=3, lockout_seconds=60)
    for _ in range(3):
        mgr.record_failure("user@test.com")
    assert mgr.is_locked("user@test.com")


def test_not_locked_before_max():
    mgr = LockoutManager(max_attempts=3, lockout_seconds=60)
    mgr.record_failure("user@test.com")
    mgr.record_failure("user@test.com")
    assert not mgr.is_locked("user@test.com")


def test_clear_resets_lockout():
    mgr = LockoutManager(max_attempts=3, lockout_seconds=60)
    for _ in range(3):
        mgr.record_failure("user@test.com")
    assert mgr.is_locked("user@test.com")
    mgr.clear("user@test.com")
    assert not mgr.is_locked("user@test.com")


def test_lockout_expires():
    mgr = LockoutManager(max_attempts=2, lockout_seconds=1)
    mgr.record_failure("user@test.com")
    mgr.record_failure("user@test.com")
    assert mgr.is_locked("user@test.com")

    # fast-forward time
    with patch("fastapi_fullauth.protection.lockout.time") as mock_time:
        mock_time.monotonic.return_value = time.monotonic() + 2
        assert not mgr.is_locked("user@test.com")


def test_separate_keys():
    mgr = LockoutManager(max_attempts=2, lockout_seconds=60)
    mgr.record_failure("a@test.com")
    mgr.record_failure("a@test.com")
    assert mgr.is_locked("a@test.com")
    assert not mgr.is_locked("b@test.com")
