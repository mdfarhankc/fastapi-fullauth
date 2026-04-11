import logging
import time

logger = logging.getLogger("fastapi_fullauth.lockout")


class LockoutManager:
    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 900) -> None:
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, key: str) -> bool:
        until = self._locked_until.get(key)
        if until is None:
            return False
        if time.monotonic() >= until:
            self.clear(key)
            return False
        return True

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        attempts = self._attempts.setdefault(key, [])
        # only keep attempts within the lockout window
        cutoff = now - self.lockout_seconds
        attempts[:] = [t for t in attempts if t > cutoff]
        attempts.append(now)

        if len(attempts) >= self.max_attempts:
            self._locked_until[key] = now + self.lockout_seconds
            logger.warning(
                "Account locked after %d failed attempts: %s",
                self.max_attempts, key,
            )

    def clear(self, key: str) -> None:
        self._attempts.pop(key, None)
        self._locked_until.pop(key, None)
