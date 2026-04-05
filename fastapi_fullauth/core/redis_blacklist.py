from fastapi_fullauth.core.tokens import TokenBlacklist


class RedisBlacklist(TokenBlacklist):
    def __init__(self, redis_url: str, default_ttl_seconds: int = 1800) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis package is required for the Redis blacklist backend. "
                "Install it with: pip install fastapi-fullauth[redis]"
            ) from None

        self._redis = aioredis.from_url(redis_url, decode_responses=True)
        self._default_ttl = default_ttl_seconds
        self._prefix = "fullauth:blacklist:"

    async def add(self, jti: str, ttl_seconds: int | None = None) -> None:
        await self._redis.setex(
            f"{self._prefix}{jti}",
            ttl_seconds or self._default_ttl,
            "1",
        )

    async def is_blacklisted(self, jti: str) -> bool:
        return await self._redis.exists(f"{self._prefix}{jti}") > 0
