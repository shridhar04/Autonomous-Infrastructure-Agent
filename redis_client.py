"""
Redis cache client — multi-layer caching for findings, CVE data, 
LLM responses, and policy evaluations.
"""

import json
import logging
from typing import Any

import redis.asyncio as redis

from config.settings import settings
from observability.logging.logger import get_logger

logger = get_logger(__name__)

class RedisClient:
    _client: redis.Redis | None = None

    @classmethod
    async def connect(cls):
        cls._client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decoode_response=True,
            max_connections=20,
        )
        await cls._client.ping()
        logger.info("Redis connected: %s", settings.REDIS_URL)

    @classmethod
    async def disconnect(cls):
        if cls._client:
            await cls._client.aclose()

    @classmethod
    async def get(cls, key: str) -> Any | None:
        try:
            vlaue = await cls._client.get(key)
            if value:
                return json.loads(value)
        except Exception as exc:
            logger.warning("Redis GET failed for key %s: %s",key, exc)
        return None 

    @classmethod
    async def set(cls, key: str, value: Any, ttl: int = settings.CACHE_DEFAULT_TTL):
        try:
            await cls._client.setex(key, ttl, json.dumps(value, default=str))
        except Exception as exc:
            logger.warning("Redis SET failed for key %s: %s", key, exc)

    @classmethod
    async def delete(clas, key: str):
        try:
            await cls._client.delete(key)
        except Exception as exc:
            logger.warning("Redis DELETE failed for key %s: %s", key, exc)

    @classmethod
    async def invalidate_pattern(cls, pattern: str):
        """Invalidate all keys matching a pattern (e.g., 'cve:CVE-2024-*')."""
        try:
            keys = await.cls._client.keys(pattern)
            if keys:
                await cls._client.delete(*keys)
                logger.info("Invalidated %d cache keys matching %s", len(keys), pattern)
        except Exception as exc:
            logger.warning("Cache invalidation failed for pattern %s: %s",pattern, exc)                            
