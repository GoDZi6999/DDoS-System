import asyncio
import json

import pytest
from sqlalchemy.exc import OperationalError

from app.models import Alert, NetworkEvent
from app.services.notify import CONFIG_KEY, EVENTS_CHANNEL
from app.workers import alert_engine
from app.workers.alert_engine import (
    CONSUMER_GROUP,
    DEAD_LETTER_STREAM,
    DETECTIONS_STREAM,
    AlertEngine,
)
from tests.helpers import count_rows, count_rows_async, detection, run


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch):
    monkeypatch.setattr(alert_engine, "BLOCK_MS", 100)
    monkeypatch.setattr(alert_engine, "RETRY_DELAY_S", 0.05)
    monkeypatch.setattr(alert_engine, "HEARTBEAT_FILE", alert_engine.Path("/dev/null"))


def _publish(redis_client, payload: str) -> str:
    return redis_client.xadd(DETECTIONS_STREAM, {"data": payload}).decode()


def _run_until(client, condition, consumer="engine-under-test", timeout=10.0) -> None:
    """Run the engine's main loop until condition() holds, then stop it."""

    async def _run() -> None:
        engine = AlertEngine(client.app.state.sessionmaker, client.app.state.redis, consumer)
        stop = asyncio.Event()
        task = asyncio.create_task(engine.run(stop))
        try:
            async with asyncio.timeout(timeout):
                while not await condition():  # noqa: ASYNC110 (polls database state)
                    await asyncio.sleep(0.05)
        finally:
            stop.set()
            await task

    run(client, _run)


def _pending(redis_client) -> int:
    return redis_client.xpending(DETECTIONS_STREAM, CONSUMER_GROUP)["pending"]


def test_detections_become_alerts_and_are_acknowledged(client, redis_client):
    pubsub = redis_client.pubsub()
    pubsub.subscribe(EVENTS_CHANNEL)
    pubsub.get_message(timeout=1)
    for src in ("198.51.100.1", "198.51.100.2"):
        _publish(redis_client, detection(src_ip=src).model_dump_json())

    async def two_events() -> bool:
        return await count_rows_async(client, NetworkEvent) == 2

    _run_until(client, two_events)

    assert count_rows(client, Alert) == 1
    assert _pending(redis_client) == 0
    assert json.loads(redis_client.get(CONFIG_KEY))["alert_min_risk"] == 31  # mirrored
    published = [json.loads(pubsub.get_message(timeout=1)["data"])["type"] for _ in range(2)]
    assert published == ["alert.new", "alert.updated"]
    pubsub.close()


def test_malformed_entries_are_dead_lettered(client, redis_client):
    _publish(redis_client, '{"label": "ddos"}')
    _publish(redis_client, detection().model_dump_json())

    async def processed() -> bool:
        return await count_rows_async(client, NetworkEvent) == 1

    _run_until(client, processed)

    dead = redis_client.xrange(DEAD_LETTER_STREAM)
    assert len(dead) == 1
    assert b"Field required" in dead[0][1][b"error"]
    assert _pending(redis_client) == 0


def test_entries_abandoned_by_a_crashed_consumer_are_reclaimed(client, redis_client, monkeypatch):
    monkeypatch.setattr(alert_engine, "STALE_AFTER_MS", 0)
    redis_client.xgroup_create(DETECTIONS_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    _publish(redis_client, detection().model_dump_json())
    # A consumer reads the entry and dies before acknowledging it.
    redis_client.xreadgroup(CONSUMER_GROUP, "crashed", {DETECTIONS_STREAM: ">"})
    assert _pending(redis_client) == 1

    async def processed() -> bool:
        return await count_rows_async(client, NetworkEvent) == 1

    _run_until(client, processed, consumer="survivor")

    assert _pending(redis_client) == 0


def test_database_failure_leaves_the_entry_pending_for_retry(client, redis_client, monkeypatch):
    entry_id = _publish(redis_client, detection().model_dump_json())
    calls = {"n": 0}
    real_ingest = alert_engine.ingest_detection

    async def flaky_ingest(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError("INSERT", {}, ConnectionError("database restarting"))
        return await real_ingest(*args, **kwargs)

    monkeypatch.setattr(alert_engine, "ingest_detection", flaky_ingest)

    async def processed() -> bool:
        return await count_rows_async(client, NetworkEvent) == 1

    _run_until(client, processed)

    assert calls["n"] == 2  # failed once, retried from the pending list
    assert _pending(redis_client) == 0
    assert redis_client.xrange(DETECTIONS_STREAM)[0][0].decode() == entry_id


def test_redelivered_entry_is_not_stored_twice(client, redis_client):
    payload = detection().model_dump_json()

    async def handle_twice() -> None:
        engine = AlertEngine(client.app.state.sessionmaker, client.app.state.redis, "dup")
        await engine.ensure_group()
        assert await engine.handle("1700000000000-0", {b"data": payload.encode()})
        assert await engine.handle("1700000000000-0", {b"data": payload.encode()})

    run(client, handle_twice)

    assert count_rows(client, NetworkEvent) == 1


def test_published_detection_schema_matches_the_model():
    """docs/schemas/detection.schema.json is the contract the real-time engine
    is tested against; regenerate it when the Detection model changes."""
    import json
    from pathlib import Path

    from app.schemas.detection import Detection

    path = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "detection.schema.json"
    assert json.loads(path.read_text()) == Detection.model_json_schema()
