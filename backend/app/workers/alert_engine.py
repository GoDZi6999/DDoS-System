"""Alert engine worker: consumes detections from Redis, stores them and raises alerts.

    python -m app.workers.alert_engine

Delivery is at-least-once through a Redis consumer group:
- an entry is acknowledged only after its database transaction commits;
- the stream entry id is stored with the event, so redelivery cannot duplicate it;
- malformed entries go to a dead-letter stream instead of blocking the queue;
- entries left pending by a crashed consumer are reclaimed after STALE_AFTER_MS.
"""

import asyncio
import logging
import signal
import socket
import time
from pathlib import Path

from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.db.session import create_engine, create_sessionmaker
from app.schemas.config import DetectionConfig
from app.schemas.detection import Detection
from app.services.alerts import ingest_detection, summarize
from app.services.detection_config import get_detection_config
from app.services.notify import mirror_detection_config, publish

logger = logging.getLogger("app.workers.alert_engine")

DETECTIONS_STREAM = "sentinel:detections"
DEAD_LETTER_STREAM = "sentinel:detections:dead"
CONSUMER_GROUP = "alert-engine"
HEARTBEAT_FILE = Path("/tmp/alert-engine.heartbeat")  # noqa: S108 (container-local health file)

BATCH_SIZE = 100
BLOCK_MS = 5000
STALE_AFTER_MS = 60_000
CLAIM_INTERVAL_S = 30.0
RETRY_DELAY_S = 2.0
CONFIG_TTL_S = 10.0
DEAD_LETTER_MAXLEN = 10_000


class AlertEngine:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        redis: Redis,
        consumer: str,
    ) -> None:
        self.sessionmaker = sessionmaker
        self.redis = redis
        self.consumer = consumer
        self._config: tuple[float, DetectionConfig] | None = None

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(DETECTIONS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def _detection_config(self, session: AsyncSession) -> DetectionConfig:
        now = time.monotonic()
        if self._config is None or now - self._config[0] > CONFIG_TTL_S:
            self._config = (now, await get_detection_config(session))
            # Keep Redis in step with the database (e.g. after a Redis restart).
            await mirror_detection_config(self.redis, self._config[1].model_dump_json())
        return self._config[1]

    async def _dead_letter(self, entry_id: str, raw: bytes | None, error: str) -> None:
        logger.warning("Dead-lettering entry %s: %s", entry_id, error[:200])
        await self.redis.xadd(
            DEAD_LETTER_STREAM,
            {"entry_id": entry_id, "error": error[:2000], "data": raw or b""},
            maxlen=DEAD_LETTER_MAXLEN,
            approximate=True,
        )
        await self.redis.xack(DETECTIONS_STREAM, CONSUMER_GROUP, entry_id)

    async def handle(self, entry_id: str, fields: dict[bytes, bytes] | None) -> bool:
        """Process one stream entry. Returns False on a transient failure, leaving
        the entry pending so it is retried."""
        raw = (fields or {}).get(b"data")
        try:
            detection = Detection.model_validate_json(raw or b"")
        except ValidationError as exc:
            await self._dead_letter(entry_id, raw, str(exc))
            return True

        try:
            async with self.sessionmaker() as session:
                config = await self._detection_config(session)
                result = await ingest_detection(session, detection, config, stream_id=entry_id)
                await session.commit()
                summary = await summarize(session, result.alert) if result.alert else None
        except IntegrityError:
            # Only the unique stream id can collide: another consumer already stored it.
            logger.info("Entry %s was already processed", entry_id)
            result, summary = None, None
        except (SQLAlchemyError, OSError):
            logger.exception("Database error while processing %s; will retry", entry_id)
            return False

        await self.redis.xack(DETECTIONS_STREAM, CONSUMER_GROUP, entry_id)
        if result is not None and summary is not None:
            event_type = "alert.new" if result.created else "alert.updated"
            await publish(self.redis, event_type, summary.model_dump(mode="json"))
        return True

    async def _process(self, entries: list) -> bool:
        for entry_id, fields in entries:
            if not await self.handle(entry_id.decode(), fields):
                return False
        return True

    async def _claim_stale(self) -> bool:
        _, entries, _ = await self.redis.xautoclaim(
            DETECTIONS_STREAM, CONSUMER_GROUP, self.consumer, STALE_AFTER_MS, count=BATCH_SIZE
        )
        return await self._process(entries)

    def _heartbeat(self) -> None:
        try:
            HEARTBEAT_FILE.write_text(str(time.time()))
        except OSError:
            logger.debug("Could not write heartbeat file", exc_info=True)

    async def run(self, stop: asyncio.Event) -> None:
        await self.ensure_group()
        logger.info("Consuming %s as %s/%s", DETECTIONS_STREAM, CONSUMER_GROUP, self.consumer)
        read_id = "0"  # start with entries this consumer already owns but never acked
        next_claim = 0.0
        while not stop.is_set():
            self._heartbeat()
            try:
                if time.monotonic() >= next_claim:
                    next_claim = time.monotonic() + CLAIM_INTERVAL_S
                    if not await self._claim_stale():
                        read_id = "0"
                        await asyncio.sleep(RETRY_DELAY_S)
                        continue
                response = await self.redis.xreadgroup(
                    CONSUMER_GROUP,
                    self.consumer,
                    {DETECTIONS_STREAM: read_id},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )
            except RedisError:
                logger.warning("Redis unavailable; retrying", exc_info=True)
                await asyncio.sleep(RETRY_DELAY_S)
                continue

            entries = response[0][1] if response else []
            if read_id == "0" and not entries:
                read_id = ">"  # backlog drained; switch to new entries
                continue
            if not await self._process(entries):
                read_id = "0"
                await asyncio.sleep(RETRY_DELAY_S)


async def _main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    # XREADGROUP blocks for up to BLOCK_MS by design, so the read timeout must be
    # longer than that (redis-py's default is 5 s).
    redis = Redis.from_url(
        settings.redis_url, socket_connect_timeout=5, socket_timeout=BLOCK_MS / 1000 + 10
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    worker = AlertEngine(create_sessionmaker(engine), redis, consumer=socket.gethostname())
    try:
        await worker.run(stop)
    finally:
        await redis.aclose()
        await engine.dispose()
        logger.info("Alert engine stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(_main())


if __name__ == "__main__":
    main()
