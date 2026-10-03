"""Output side of the engine: Redis in production, memory in tests.

- detections -> Redis stream `sentinel:detections` (consumed by the alert
  engine; contract in docs/API.md and docs/schemas/detection.schema.json)
- live traffic counters -> pub/sub channel `sentinel:events` as `traffic.tick`
  (forwarded to dashboards by the API's WebSocket)
- detection settings <- Redis key `sentinel:config:detection` (written by the API)
"""

import json
import logging

import redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

DETECTIONS_STREAM = "sentinel:detections"
EVENTS_CHANNEL = "sentinel:events"
CONFIG_KEY = "sentinel:config:detection"
STREAM_MAXLEN = 100_000


class RedisPublisher:
    def __init__(self, url: str) -> None:
        self.redis = redis.Redis.from_url(url, socket_connect_timeout=5, socket_timeout=10)

    def detections(self, items: list[dict]) -> None:
        if not items:
            return
        pipe = self.redis.pipeline(transaction=False)
        for item in items:
            pipe.xadd(
                DETECTIONS_STREAM,
                {"data": json.dumps(item)},
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
        pipe.execute()

    def event(self, event_type: str, data: dict) -> None:
        try:
            self.redis.publish(EVENTS_CHANNEL, json.dumps({"type": event_type, "data": data}))
        except RedisError:
            logger.warning("Could not publish %s", event_type, exc_info=True)

    def detection_config(self) -> dict | None:
        try:
            raw = self.redis.get(CONFIG_KEY)
        except RedisError:
            logger.warning("Could not read detection settings", exc_info=True)
            return None
        return json.loads(raw) if raw else None


class MemoryPublisher:
    def __init__(self, config: dict | None = None) -> None:
        self.published: list[dict] = []
        self.events: list[tuple[str, dict]] = []
        self.config = config

    def detections(self, items: list[dict]) -> None:
        self.published.extend(items)

    def event(self, event_type: str, data: dict) -> None:
        self.events.append((event_type, data))

    def detection_config(self) -> dict | None:
        return self.config
