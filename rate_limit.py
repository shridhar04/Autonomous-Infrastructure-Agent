"""
Sliding window rate limiter using Redis.
Prevents API abuse and protects LLM quota.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from storage.cache.redis_client import RedisClient
from config.settings import settings
import time


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.rpm = requests_per_minute

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        user_id = getattr(request.state, "user_id", client_ip)

        key = f"rate:{user_id}:{int(time.time() // 60)}"
        count = await RedisClient.get(key) or 0

        if int(count) >= self.rpm:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Retry after 60 seconds."},
                headers={"Retry-After": "60"},
            )

        # Increment counter (TTL 90s to cover window boundary)
        await RedisClient.set(key, int(count) + 1, ttl=90)
        return await call_next(request)
