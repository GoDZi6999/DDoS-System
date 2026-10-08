"""Notifier worker: sends queued alert notifications and enforces retention.

    python -m app.workers.notifier

Deliveries are rows in notification_deliveries (the outbox), queued by the
alert engine in the same transaction as the alert change. Each one is locked
with SELECT ... FOR UPDATE SKIP LOCKED while it is sent, so several workers
can run side by side without sending anything twice. Failed attempts are
retried with backoff; after MAX_ATTEMPTS, or on a permanent error, the
delivery is marked failed with the reason.
"""

import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import create_engine, create_sessionmaker
from app.models import NotificationChannel, NotificationDelivery
from app.models.enums import DeliveryStatus
from app.services.retention import purge
from app.services.senders import DeliveryError, send_delivery

logger = logging.getLogger("app.workers.notifier")

HEARTBEAT_FILE = Path("/tmp/notifier.heartbeat")  # noqa: S108 (container-local health file)
POLL_INTERVAL_S = 2.0
SEND_TIMEOUT_S = 30.0
MAX_ATTEMPTS = 5
# Wait before attempt 2, 3, 4 and 5.
BACKOFF_S = (30, 120, 600, 1800)
RETENTION_INTERVAL_S = 6 * 3600

Sender = Callable[
    [NotificationChannel, NotificationDelivery, httpx2.AsyncClient, Settings], Awaitable[None]
]


class Notifier:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        client: httpx2.AsyncClient,
        settings: Settings,
        sender: Sender = send_delivery,
    ) -> None:
        self.sessionmaker = sessionmaker
        self.client = client
        self.settings = settings
        self.sender = sender

    def _record_failure(self, delivery: NotificationDelivery, error: str, permanent: bool) -> None:
        delivery.last_error = error[:1000]
        if permanent or delivery.attempts >= MAX_ATTEMPTS:
            delivery.status = DeliveryStatus.FAILED
        else:
            wait = BACKOFF_S[min(delivery.attempts, len(BACKOFF_S)) - 1]
            delivery.next_attempt_at = datetime.now(UTC) + timedelta(seconds=wait)

    async def process_one(self) -> bool:
        """Send the next due delivery, if any. Returns False when none is due."""
        async with self.sessionmaker() as session:
            delivery = await session.scalar(
                select(NotificationDelivery)
                .where(
                    NotificationDelivery.status == DeliveryStatus.PENDING,
                    NotificationDelivery.next_attempt_at <= func.now(),
                )
                .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if delivery is None:
                return False
            channel = await session.get(NotificationChannel, delivery.channel_id)
            if channel is None or not channel.enabled:
                delivery.status = DeliveryStatus.SUPPRESSED
                delivery.last_error = "Channel disabled before the notification was sent"
                await session.commit()
                return True

            delivery.attempts += 1
            try:
                await asyncio.wait_for(
                    self.sender(channel, delivery, self.client, self.settings), SEND_TIMEOUT_S
                )
            except DeliveryError as exc:
                self._record_failure(delivery, str(exc), exc.permanent)
            except TimeoutError:
                self._record_failure(delivery, "Timed out", permanent=False)
            except Exception as exc:  # a bug in a sender must not stop the worker
                logger.exception("Unexpected error sending delivery %s", delivery.id)
                self._record_failure(delivery, f"Internal error: {type(exc).__name__}", False)
            else:
                delivery.status = DeliveryStatus.SENT
                delivery.sent_at = datetime.now(UTC)
                delivery.last_error = None
            logger.info(
                "Delivery %s (%s, channel %r) -> %s after %d attempt(s)",
                delivery.id,
                delivery.event,
                channel.name,
                delivery.status,
                delivery.attempts,
            )
            await session.commit()
            return True

    async def drain(self, stop: asyncio.Event) -> int:
        sent = 0
        while not stop.is_set() and await self.process_one():
            sent += 1
        return sent

    async def purge(self) -> None:
        async with self.sessionmaker() as session:
            result = await purge(session, self.settings)
        if result.events or result.deliveries:
            logger.info(
                "Retention: deleted %d flows and %d deliveries", result.events, result.deliveries
            )

    def _heartbeat(self) -> None:
        try:
            HEARTBEAT_FILE.write_text(str(time.time()))
        except OSError:
            logger.debug("Could not write heartbeat file", exc_info=True)

    async def run(self, stop: asyncio.Event) -> None:
        logger.info("Notifier started")
        next_purge = time.monotonic() + 60  # let the stack settle first
        while not stop.is_set():
            self._heartbeat()
            try:
                await self.drain(stop)
                if time.monotonic() >= next_purge:
                    next_purge = time.monotonic() + RETENTION_INTERVAL_S
                    await self.purge()
            except (SQLAlchemyError, OSError):
                logger.warning("Database unavailable; retrying", exc_info=True)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), POLL_INTERVAL_S)


async def _main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    async with httpx2.AsyncClient(follow_redirects=False) as client:
        worker = Notifier(create_sessionmaker(engine), client, settings)
        try:
            await worker.run(stop)
        finally:
            await engine.dispose()
            logger.info("Notifier stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(_main())


if __name__ == "__main__":
    main()
