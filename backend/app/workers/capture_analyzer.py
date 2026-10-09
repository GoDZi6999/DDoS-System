"""Capture worker: analyses uploaded packet captures.

    python -m app.workers.capture_analyzer

Claims queued captures one at a time (SELECT ... FOR UPDATE SKIP LOCKED, so
several workers can share the queue) and replays each through the real-time
engine at full speed (app/services/capture_analysis.py). With `raise_alerts`,
detections go to the alert engine's Redis stream like live traffic, tagged
with the capture id so alerts can serve their packets as evidence.

Needs the engine and ML packages (sentinel_engine, sentinel_ml, Scapy) and a
model bundle (MODEL_BUNDLE), as the backend image provides.
"""

import asyncio
import contextlib
import logging
import signal
import time
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import create_engine, create_sessionmaker
from app.services import captures as capture_service
from app.services.capture_analysis import CaptureError, analyze
from app.services.detector import DetectorUnavailable, get_detector

logger = logging.getLogger("app.workers.capture_analyzer")

HEARTBEAT_FILE = Path("/tmp/capture-worker.heartbeat")  # noqa: S108 (container-local health file)
POLL_INTERVAL_S = 2.0
HEARTBEAT_INTERVAL_S = 5.0


class CaptureWorker:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], settings: Settings) -> None:
        self.sessionmaker = sessionmaker
        self.settings = settings

    def _publisher(self):
        from sentinel_engine.publisher import RedisPublisher

        return RedisPublisher(self.settings.redis_url)

    def _analyze(self, path: Path, capture_id: int, raise_alerts: bool):
        predictor = get_detector().predictor
        forward = self._publisher() if raise_alerts else None
        return analyze(path, capture_id, predictor, forward)

    async def process_one(self) -> bool:
        """Analyse the next queued capture; False when the queue is empty."""
        async with self.sessionmaker() as session:
            capture = await capture_service.claim_next(session)
        if capture is None:
            return False
        path = capture_service.capture_path(self.settings, capture)
        logger.info("Analysing capture %d (%s)", capture.id, capture.filename)
        try:
            result = await asyncio.to_thread(self._analyze, path, capture.id, capture.raise_alerts)
        except (CaptureError, DetectorUnavailable, OSError) as exc:
            logger.warning("Capture %d failed: %s", capture.id, exc)
            async with self.sessionmaker() as session:
                await capture_service.finish(session, capture.id, error=str(exc))
            return True
        except Exception:
            logger.exception("Capture %d failed", capture.id)
            async with self.sessionmaker() as session:
                await capture_service.finish(
                    session, capture.id, error="Analysis failed unexpectedly; see the worker log"
                )
            return True
        async with self.sessionmaker() as session:
            await capture_service.finish(
                session, capture.id, report=result.report, time_offset=result.time_offset
            )
        logger.info(
            "Capture %d: %d packets, %d flows, %d attack detections",
            capture.id,
            result.report["packets"],
            result.report["flows"],
            result.report["attacks"],
        )
        return True

    @staticmethod
    def _touch() -> None:
        try:
            HEARTBEAT_FILE.write_text(str(time.time()))
        except OSError:
            logger.debug("Could not write heartbeat file", exc_info=True)

    async def _heartbeat(self, stop: asyncio.Event) -> None:
        # Its own task, so a long analysis (in a thread) does not look like a hang.
        while not stop.is_set():
            self._touch()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), HEARTBEAT_INTERVAL_S)

    async def run(self, stop: asyncio.Event) -> None:
        logger.info("Capture worker started")
        heartbeat = asyncio.create_task(self._heartbeat(stop))
        recovered = False
        try:
            while not stop.is_set():
                try:
                    if not recovered:
                        async with self.sessionmaker() as session:
                            if count := await capture_service.fail_interrupted(session):
                                logger.warning("Marked %d interrupted captures as failed", count)
                        recovered = True
                    while not stop.is_set() and await self.process_one():
                        pass
                except (SQLAlchemyError, OSError):
                    logger.warning("Database unavailable; retrying", exc_info=True)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), POLL_INTERVAL_S)
        finally:
            heartbeat.cancel()


async def _main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await CaptureWorker(create_sessionmaker(engine), settings).run(stop)
    finally:
        await engine.dispose()
        logger.info("Capture worker stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(_main())


if __name__ == "__main__":
    main()
