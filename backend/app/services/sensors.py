"""Capture sensor status, read from what sensors and the engine keep in Redis.

Sensors refresh `sentinel:sensors:<name>` every few seconds (contract:
engine/sentinel_engine/flowstream.py); the key expires a day after the last
update, so offline sensors stay listed for a while.
"""

import logging
import time
from datetime import UTC, datetime

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.schemas.sensor import Sensor, SensorBacklog, SensorList, SensorStatus

logger = logging.getLogger(__name__)

SENSOR_KEY_PATTERN = "sentinel:sensors:*"
FLOWS_STREAM = "sentinel:flows"
ENGINE_GROUP = "engine"
ONLINE_S = 15.0
STALE_S = 60.0
MAX_SENSORS = 500


def _text(raw: dict, key: str, limit: int = 256) -> str:
    value = raw.get(key.encode(), b"")
    return value.decode(errors="replace")[:limit]


def _number(raw: dict, key: str) -> float:
    try:
        return max(float(raw.get(key.encode(), 0)), 0.0)
    except ValueError:
        return 0.0


def _time(raw: dict, key: str) -> datetime | None:
    value = _number(raw, key)
    return datetime.fromtimestamp(value, UTC) if value else None


def status_of(raw: dict, now: float) -> SensorStatus:
    age = now - _number(raw, "last_seen")
    if _text(raw, "state") == "stopped" or age > STALE_S:
        return "offline"
    return "online" if age <= ONLINE_S else "stale"


def _sensor(key: bytes, raw: dict, now: float) -> Sensor:
    return Sensor(
        name=_text(raw, "name", 64) or key.decode(errors="replace").rsplit(":", 1)[-1],
        status=status_of(raw, now),
        hostname=_text(raw, "hostname", 128),
        platform=_text(raw, "platform", 64),
        interface=_text(raw, "interface", 128),
        filter=_text(raw, "filter"),
        started_at=_time(raw, "started_at"),
        last_seen=_time(raw, "last_seen"),
        packets=int(_number(raw, "packets")),
        packets_per_s=_number(raw, "packets_per_s"),
        flows_sent=int(_number(raw, "flows_sent")),
        flows_buffered=int(_number(raw, "flows_buffered")),
        flows_dropped=int(_number(raw, "flows_dropped")),
        capture_drops=int(_number(raw, "capture_drops")),
        active_flows=int(_number(raw, "active_flows")),
    )


async def _backlog(redis: Redis) -> SensorBacklog | None:
    try:
        groups = await redis.xinfo_groups(FLOWS_STREAM)
    except RedisError:  # no stream yet: no sensor has sent anything
        return None
    for group in groups:
        if group.get("name") in (ENGINE_GROUP, ENGINE_GROUP.encode()):
            lag = group.get("lag")
            return SensorBacklog(pending=int(group.get("pending", 0)), lag=lag)
    return None


async def list_sensors(redis: Redis) -> SensorList:
    now = time.time()
    keys = []
    async for key in redis.scan_iter(match=SENSOR_KEY_PATTERN, count=200):
        keys.append(key)
        if len(keys) >= MAX_SENSORS:
            break
    sensors = []
    for key in keys:
        raw = await redis.hgetall(key)
        if raw:
            sensors.append(_sensor(key, raw, now))
    order = {"online": 0, "stale": 1, "offline": 2}
    sensors.sort(key=lambda s: (order[s.status], s.name.lower()))
    return SensorList(items=sensors, backlog=await _backlog(redis))
