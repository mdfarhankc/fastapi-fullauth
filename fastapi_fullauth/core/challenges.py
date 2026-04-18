"""Challenge store for WebAuthn passkey flows.

Challenges are short-lived, single-use nonces that prevent replay attacks.
The server generates a challenge, sends it to the browser, and the browser
signs it with the user's private key. The server verifies the signature
and deletes the challenge.
"""

import logging
import time
from abc import ABC, abstractmethod

logger = logging.getLogger("fastapi_fullauth.challenges")


class ChallengeStore(ABC):
    """Abstract challenge store. Stores challenges with a TTL."""

    @abstractmethod
    async def store(self, key: str, challenge: str, ttl: int = 60) -> None: ...

    @abstractmethod
    async def pop(self, key: str) -> str | None:
        """Retrieve and delete a challenge. Returns None if expired or missing."""
        ...


class InMemoryChallengeStore(ChallengeStore):
    """In-memory challenge store. Single-process only."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float]] = {}

    async def store(self, key: str, challenge: str, ttl: int = 60) -> None:
        self._store[key] = (challenge, time.monotonic() + ttl)

    async def pop(self, key: str) -> str | None:
        entry = self._store.pop(key, None)
        if entry is None:
            return None
        challenge, expires_at = entry
        if time.monotonic() > expires_at:
            return None
        return challenge


class RedisChallengeStore(ChallengeStore):
    """Redis-backed challenge store. Works across multiple workers."""

    def __init__(self, redis_url: str) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for the Redis challenge store. "
                "Install it with: pip install fastapi-fullauth[redis]"
            ) from None

        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._prefix = "fullauth:challenge:"

    async def store(self, key: str, challenge: str, ttl: int = 60) -> None:
        await self._redis.setex(f"{self._prefix}{key}", ttl, challenge)

    async def pop(self, key: str) -> str | None:
        redis_key = f"{self._prefix}{key}"
        challenge = await self._redis.getdel(redis_key)
        return challenge


_challenge_store_registry: dict[str, type[ChallengeStore]] = {
    "memory": InMemoryChallengeStore,
    "redis": RedisChallengeStore,
}


def register_challenge_store_backend(name: str, cls: type[ChallengeStore]) -> None:
    """Register a custom challenge store backend."""
    _challenge_store_registry[name] = cls


def create_challenge_store(config) -> ChallengeStore:
    """Create a challenge store based on config."""
    backend = config.PASSKEY_CHALLENGE_BACKEND
    backend_cls = _challenge_store_registry.get(backend)
    if backend_cls is None:
        raise ValueError(
            f"Unknown challenge store backend: {backend}. "
            f"Available: {', '.join(sorted(_challenge_store_registry))}."
        )

    if backend == "redis":
        if not config.REDIS_URL:
            raise ValueError("REDIS_URL must be set when PASSKEY_CHALLENGE_BACKEND='redis'")
        return RedisChallengeStore(redis_url=config.REDIS_URL)

    return backend_cls()
