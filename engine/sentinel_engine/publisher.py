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
# Detections kept in memory while Redis is unreachable (oldest dropped first).
MAX_PENDING = 50_000


class RedisPublisher:
    def __init__(self, url: str) -> None:
        self.redis = redis.Redis.from_url(url, socket_connect_timeout=5, socket_timeout=10)
        self.pending: list[dict] = []

    def detections(self, items: list[dict]) -> None:
        """Send detections; if Redis is down, keep them (bounded) and retry
        on the next call, so a short outage neither kills the engine (and its
        flow, window and baseline state) nor loses detections. If a pipeline
        fails part-way, entries already written may be sent again."""
        self.pending.extend(items)
        if not self.pending:
            return
        pipe = self.redis.pipeline(transaction=False)
        for item in self.pending:
            pipe.xadd(
                DETECTIONS_STREAM,
                {"data": json.dumps(item)},
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
        try:
            pipe.execute()
        except RedisError:
            dropped = max(len(self.pending) - MAX_PENDING, 0)
            if dropped:
                self.pending = self.pending[dropped:]
            logger.warning(
                "Redis unavailable: %d detections buffered, %d dropped",
                len(self.pending),
                dropped,
                exc_info=True,
            )
            return
        self.pending = []

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
