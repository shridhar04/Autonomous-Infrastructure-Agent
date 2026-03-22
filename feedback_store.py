"""
Feedback Store — persists developer feedback for AI model fine-tuning.
"""
from typing import Dict, Any
from storage.cache.redis_client import RedisClient
from observability.logging.logger import get_logger

logger = get_logger(__name__)


class FeedbackStore:
    async def record(self, finding_id: str, action: str, comment: str = "") -> bool:
        key = f"feedback:{finding_id}"
        try:
            await RedisClient.set(key, {"action": action, "comment": comment}, ttl=86400 * 90)
            logger.info("Feedback recorded: finding=%s action=%s", finding_id, action)
            return True
        except Exception as exc:
            logger.error("Feedback store failed: %s", exc)
            return False

    async def get_false_positive_rate(self, rule_id: str) -> float:
        """Estimate false positive rate for a rule from stored feedback."""
        # In production: query PostgreSQL finding_feedback table
        return 0.0
