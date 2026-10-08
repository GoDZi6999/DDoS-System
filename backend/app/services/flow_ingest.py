"""POST /v2/flows: hand flows to the real-time engine over the sensor stream.

Entries follow the sensor wire contract (engine/sentinel_engine/flowstream.py),
so an engine running with `--source sensor` classifies them, scores risk and
feeds the normal alert pipeline, exactly as for a capture sensor. Each API key
shows up in the dashboard's sensor list as `api-<prefix>`.
"""

import json
import socket
import time

from redis.asyncio import Redis

from app.schemas.flow import FlowRecord

PROTOCOL_VERSION = 1
FLOWS_STREAM = "sentinel:flows"
FLOWS_MAXLEN = 200_000
SENSOR_KEY_PREFIX = "sentinel:sensors:"
SENSOR_KEY_TTL_S = 86_400


def sensor_name(prefix: str) -> str:
    return f"api-{prefix}"


async def ingest(redis: Redis, prefix: str, flows: list[FlowRecord]) -> str:
    name = sensor_name(prefix)
    now = time.time()
    key = SENSOR_KEY_PREFIX + name
    async with redis.pipeline(transaction=False) as pipe:
        for flow in flows:
            data = json.dumps(flow.model_dump(mode="json"))
            pipe.xadd(
                FLOWS_STREAM,
                {"v": str(PROTOCOL_VERSION), "sensor": name, "data": data},
                maxlen=FLOWS_MAXLEN,
                approximate=True,
            )
        pipe.hsetnx(key, "started_at", now)
        pipe.hset(
            key,
            mapping={
                "name": name,
                "hostname": socket.gethostname(),
                "platform": "API",
                "interface": "POST /v2/flows",
                "state": "running",
                "last_seen": now,
            },
        )
        pipe.hincrby(key, "flows_sent", len(flows))
        pipe.expire(key, SENSOR_KEY_TTL_S)
        await pipe.execute()
    return name
