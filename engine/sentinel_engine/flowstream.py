"""Wire contract between capture sensors and the engine.

Sensors build flows where the traffic is and append one entry per finished
flow to the Redis stream `sentinel:flows`; the engine (`run --source sensor`)
reads them with a consumer group and classifies them. Each sensor also keeps
a status hash `sentinel:sensors:<name>` up to date, which the API serves to
the dashboard.

Stream entry fields: `v` (protocol version), `sensor` (name) and `data`
(JSON flow record, as produced by flows.Flow.record()). Version 2 adds the
optional booleans `preview` (an early look at a flow still open, for the
cross-flow rules only) and `previewed` (a finished flow whose preview was
already sent); version 1 entries, such as /v2/flows submissions, are
finished flows. Sensors are remote
and only trusted as far as their Redis credentials go, so every entry is
validated before it reaches the classifier.

Imports nothing beyond the standard library and flows.py, so sensors need
neither the ML stack nor pandas.
"""

import ipaddress
import json
import logging
import math
import re
import time

from sentinel_engine.flows import Flow
from sentinel_engine.packets import Packet

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 2
ACCEPTED_VERSIONS = {1, 2}
FLOWS_STREAM = "sentinel:flows"
FLOWS_MAXLEN = 200_000
SENSOR_KEY_PREFIX = "sentinel:sensors:"
SENSOR_KEY_TTL_S = 86_400  # offline sensors stay visible for a day
ENGINE_GROUP = "engine"

SENSOR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROTOCOLS = {"tcp", "udp", "icmp", "other"}
FEATURE_KEYS = frozenset(Flow.open(Packet(0.0, "a", "b", 0, 0, "tcp", 0)).features())
MAX_FLOW_S = 3_600.0
MAX_CLOCK_SKEW_S = 86_400.0
MAX_ENTRY_BYTES = 16_384


def sensor_key(name: str) -> str:
    return SENSOR_KEY_PREFIX + name


def encode(record: dict, sensor: str) -> dict[str, str]:
    return {"v": str(PROTOCOL_VERSION), "sensor": sensor, "data": json.dumps(record)}


def _text(value) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _number(value, low: float, high: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) and low <= value <= high else None


def _integer(value, low: int, high: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def decode(fields: dict, now: float | None = None) -> tuple[str, dict] | None:
    """Stream entry -> (sensor name, flow record), or None when it is malformed."""
    fields = {_text(k): v for k, v in fields.items()}
    try:
        version = int(_text(fields.get("v", "")))
        sensor = _text(fields.get("sensor", ""))
        raw = fields.get("data", b"")
        if len(raw) > MAX_ENTRY_BYTES:
            return None
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if (
        version not in ACCEPTED_VERSIONS
        or not SENSOR_NAME.match(sensor)
        or not isinstance(data, dict)
    ):
        return None

    now = time.time() if now is None else now
    record = {
        "src_ip": _ip(data.get("src_ip")),
        "dst_ip": _ip(data.get("dst_ip")),
        "src_port": _integer(data.get("src_port"), 0, 65_535),
        "dst_port": _integer(data.get("dst_port"), 0, 65_535),
        "protocol": data.get("protocol") if data.get("protocol") in PROTOCOLS else None,
        "start": _number(data.get("start"), now - MAX_CLOCK_SKEW_S, now + MAX_CLOCK_SKEW_S),
        "end": _number(data.get("end"), now - MAX_CLOCK_SKEW_S, now + MAX_CLOCK_SKEW_S),
        "packet_count": _integer(data.get("packet_count"), 1, 10**9),
        "byte_count": _integer(data.get("byte_count"), 0, 10**13),
        "duration": _number(data.get("duration"), 0.0, MAX_FLOW_S),
    }
    if any(value is None for value in record.values()) or record["end"] < record["start"]:
        return None

    features = data.get("features")
    if not isinstance(features, dict) or set(features) != FEATURE_KEYS:
        return None
    clean = {}
    for name, value in features.items():
        number = _number(value, -1.0, 1e15)
        if number is None:
            return None
        clean[name] = number
    record["features"] = clean
    for flag in ("preview", "previewed"):
        value = data.get(flag, False)
        if not isinstance(value, bool) or (value and version < 2):
            return None
        record[flag] = value
    if record["preview"] and record["previewed"]:
        return None
    return sensor, record
