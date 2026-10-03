"""Real-time notifications for connected dashboards (Redis pub/sub -> WebSocket)."""

import json
import logging
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

EVENTS_CHANNEL = "sentinel:events"


async def publish(redis: Redis, event_type: str, data: dict[str, Any]) -> None:
    """Best effort: the database stays the source of truth, so a lost
    notification only delays what a dashboard shows until its next refresh."""
    try:
        await redis.publish(EVENTS_CHANNEL, json.dumps({"type": event_type, "data": data}))
    except RedisError:
        logger.warning("Could not publish %s notification", event_type, exc_info=True)
