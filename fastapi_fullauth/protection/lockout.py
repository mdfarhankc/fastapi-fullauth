import logging
import time
from abc import ABC, abstractmethod

logger = logging.getLogger("fastapi_fullauth.lockout")


class LockoutManager(ABC):
    """Abstract lockout manager interface."""

    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 900) -> None:
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds

    @abstractmethod
    async def is_locked(self, key: str) -> bool: ...

    @abstractmethod
    async def record_failure(self, key: str) -> None: ...

    @abstractmethod
    async def clear(self, key: str) -> None: ...


class InMemoryLockoutManager(LockoutManager):
    """In-memory lockout manager. Works for single-process deployments."""

    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 900) -> None:
        super().__init__(max_attempts, lockout_seconds)
        self._attempts: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    async def is_locked(self, key: str) -> bool:
        until = self._locked_until.get(key)
        if until is None:
            return False
        if time.monotonic() >= until:
            await self.clear(key)
            return False
        return True

    async def record_failure(self, key: str) -> None:
        now = time.monotonic()
        attempts = self._attempts.setdefault(key, [])
        cutoff = now - self.lockout_seconds
        attempts[:] = [t for t in attempts if t > cutoff]
        attempts.append(now)

        if len(attempts) >= self.max_attempts:
            self._locked_until[key] = now + self.lockout_seconds
            logger.warning(
                "Account locked after %d failed attempts: %s",
                self.max_attempts,
                key,
            )

    async def clear(self, key: str) -> None:
        self._attempts.pop(key, None)
        self._locked_until.pop(key, None)


class RedisLockoutManager(LockoutManager):
    """Redis-backed lockout manager. Works across multiple workers."""

    def __init__(
        self,
        redis_url: str,
        max_attempts: int = 5,
        lockout_seconds: int = 900,
    ) -> None:
        super().__init__(max_attempts, lockout_seconds)
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for the Redis lockout manager. "
                "Install it with: pip install fastapi-fullauth[redis]"
            ) from None

        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._prefix = "fullauth:lockout:"

    async def is_locked(self, key: str) -> bool:
        locked = await self._redis.get(f"{self._prefix}locked:{key}")
        return locked is not None

    async def record_failure(self, key: str) -> None:
        attempts_key = f"{self._prefix}attempts:{key}"
        locked_key = f"{self._prefix}locked:{key}"

        pipe = self._redis.pipeline()
        pipe.incr(attempts_key)
        pipe.expire(attempts_key, self.lockout_seconds)
        results = await pipe.execute()

        count = results[0]
        if count >= self.max_attempts:
            await self._redis.setex(locked_key, self.lockout_seconds, "1")
            await self._redis.delete(attempts_key)
            logger.warning(
                "Account locked after %d failed attempts: %s",
                self.max_attempts,
                key,
            )

    async def clear(self, key: str) -> None:
        pipe = self._redis.pipeline()
        pipe.delete(f"{self._prefix}attempts:{key}")
        pipe.delete(f"{self._prefix}locked:{key}")
        await pipe.execute()


def create_lockout(config) -> LockoutManager | None:
    """Create a lockout manager based on config. Returns None if disabled."""
    if not config.LOCKOUT_ENABLED:
        return None

    if config.LOCKOUT_BACKEND == "redis":
        if not config.REDIS_URL:
            raise ValueError("REDIS_URL must be set when LOCKOUT_BACKEND='redis'")
        return RedisLockoutManager(
            redis_url=config.REDIS_URL,
            max_attempts=config.MAX_LOGIN_ATTEMPTS,
            lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
        )
    return InMemoryLockoutManager(
        max_attempts=config.MAX_LOGIN_ATTEMPTS,
        lockout_seconds=config.LOCKOUT_DURATION_MINUTES * 60,
    )
