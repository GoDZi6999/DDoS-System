import json
from pathlib import Path

import jsonschema
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from sentinel_ml.inference import Predictor

from sentinel_engine import flowstream
from sentinel_engine.packets import Heartbeat, Packet
from sentinel_engine.pipeline import Engine
from sentinel_engine.publisher import MemoryPublisher
from sentinel_engine.sensor import Sensor
from sentinel_engine.sources import sensor_source

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "models" / "sentinel-flow" / "2026.10.03"
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "detection.schema.json").read_text())
T0 = 1_790_000_000.0
C, S = "192.168.1.20", "93.184.216.34"


class FakeRedis:
    """Just enough of redis-py for the sensor and the sensor source."""

    def __init__(self) -> None:
        self.stream: list[tuple[bytes, dict]] = []
        self.hashes: dict[str, dict] = {}
        self.ttl: dict[str, int] = {}
        self.groups: dict[str, dict] = {}
        self.down = False
        self._seq = 0

    # writes (through pipelines)
    def pipeline(self, transaction=True):
        return FakePipeline(self)

    def _xadd(self, name, fields, maxlen=None, approximate=True):
        assert name == flowstream.FLOWS_STREAM
        self._seq += 1
        entry_id = f"{self._seq}-0".encode()
        self.stream.append((entry_id, {k.encode(): v.encode() for k, v in fields.items()}))
        return entry_id

    # consumer group reads
    def xgroup_create(self, name, group, id="$", mkstream=False):
        if group in self.groups:
            raise ResponseError("BUSYGROUP Consumer Group name already exists")
        self.groups[group] = {"next": len(self.stream), "pending": {}}

    def xreadgroup(self, group, consumer, streams, count=None, block=None):
        state = self.groups[group]
        cursor = streams[flowstream.FLOWS_STREAM]
        if cursor == "0":
            mine = [e for e in self.stream if state["pending"].get(e[0]) == consumer]
            entries = mine[:count]
        else:
            entries = self.stream[state["next"] : state["next"] + count]
            state["next"] += len(entries)
            for entry_id, _ in entries:
                state["pending"][entry_id] = consumer
        return [[flowstream.FLOWS_STREAM.encode(), entries]] if entries else []

    def xack(self, name, group, *ids):
        for entry_id in ids:
            self.groups[group]["pending"].pop(entry_id, None)
        return len(ids)


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis = redis
        self.ops: list = []

    def xadd(self, *args, **kwargs):
        self.ops.append(("xadd", args, kwargs))

    def hset(self, key, mapping):
        self.ops.append(("hset", (key, mapping), {}))

    def expire(self, key, seconds):
        self.ops.append(("expire", (key, seconds), {}))

    def execute(self):
        if self.redis.down:
            raise RedisConnectionError("Connection refused")
        for op, args, kwargs in self.ops:
            if op == "xadd":
                self.redis._xadd(*args, **kwargs)
            elif op == "hset":
                self.redis.hashes[args[0]] = dict(args[1])
            else:
                self.redis.ttl[args[0]] = args[1]


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def tcp(ts, src, dst, sport, dport, payload=0, flags="A", window=None):
    return Packet(ts, src, dst, sport, dport, "tcp", payload, flags, window)


def https_session(t0: float, sport: int = 50000) -> list[Packet]:
    return [
        tcp(t0 + 0.00, C, S, sport, 443, 0, "S", 64240),
        tcp(t0 + 0.02, S, C, 443, sport, 0, "SA", 65535),
        tcp(t0 + 0.03, C, S, sport, 443, 0, "A"),
        tcp(t0 + 0.04, C, S, sport, 443, 517, "PA"),
        tcp(t0 + 0.07, S, C, 443, sport, 1400, "A"),
        tcp(t0 + 0.08, S, C, 443, sport, 900, "PA"),
        tcp(t0 + 0.10, C, S, sport, 443, 0, "FA"),
        tcp(t0 + 0.11, S, C, 443, sport, 0, "FA"),
        tcp(t0 + 0.12, C, S, sport, 443, 0, "A"),
    ]


def capture(packets: list[Packet], until: float) -> list:
    """Packets followed by one Heartbeat per second (what live_source yields)."""
    last = packets[-1].ts
    beats = [Heartbeat(last + i) for i in range(1, int(until - last) + 1)]
    return [*packets, *beats]


def drain(source, limit: int = 1000) -> list[dict]:
    """Records from sensor_source until it reports an idle stream."""
    records = []
    for item in source:
        if isinstance(item, Heartbeat):
            return records
        records.append(item)
        assert len(records) < limit
    return records


def test_sensor_ships_valid_flows_and_status():
    redis, clock = FakeRedis(), Clock()
    sensor = Sensor(redis, "laptop", "Wi-Fi", "tcp or udp", clock=clock)

    sensor.run(capture(https_session(T0) + https_session(T0 + 0.5, 50001), until=T0 + 3))

    decoded = [flowstream.decode(fields, T0) for _, fields in redis.stream]
    assert [d[0] for d in decoded] == ["laptop", "laptop"]
    first = decoded[0][1]
    assert (first["src_ip"], first["dst_ip"], first["dst_port"]) == (C, S, 443)
    assert first["packet_count"] == 9 and first["byte_count"] == 517 + 1400 + 900
    assert first["features"]["syn_flag_count"] == 2

    status = redis.hashes["sentinel:sensors:laptop"]
    assert status["state"] == "stopped"
    assert status["packets"] == 18 and status["flows_sent"] == 2
    assert status["interface"] == "Wi-Fi" and status["filter"] == "tcp or udp"
    assert redis.ttl["sentinel:sensors:laptop"] == flowstream.SENSOR_KEY_TTL_S


def test_sensor_buffers_while_the_stack_is_down_and_catches_up():
    redis, clock = FakeRedis(), Clock()
    sensor = Sensor(redis, "edge-1", clock=clock, buffer_max=3)
    redis.down = True

    sensor._queue([{"n": i} for i in range(5)])
    sensor.flush()
    assert not redis.stream and len(sensor.buffer) == 3 and sensor.flows_dropped == 2
    assert not sensor.connected

    redis.down = False
    sensor.flush()  # still backing off
    assert not redis.stream
    clock.now += 2
    sensor.flush()
    assert [json.loads(f[b"data"]) for _, f in redis.stream] == [{"n": 2}, {"n": 3}, {"n": 4}]
    assert sensor.connected and sensor.flows_sent == 3 and not sensor.buffer


def test_invalid_sensor_name_is_refused():
    with pytest.raises(ValueError):
        Sensor(FakeRedis(), "bad name; rm -rf")


def valid_entry() -> dict:
    redis = FakeRedis()
    Sensor(redis, "s1", clock=Clock()).run(capture(https_session(T0), until=T0 + 2))
    return {k.decode(): v.decode() for k, v in redis.stream[0][1].items()}


def mutate(entry: dict, **changes) -> dict:
    data = json.loads(entry["data"])
    for key, value in changes.items():
        if key.startswith("f_"):
            data["features"][key[2:]] = value
        else:
            data[key] = value
    return {**entry, "data": json.dumps(data)}


@pytest.mark.parametrize(
    "change",
    [
        {"src_ip": "not-an-ip"},
        {"dst_port": 70000},
        {"protocol": "sctp"},
        {"packet_count": 0},
        {"packet_count": True},
        {"duration": -1},
        {"end": T0 - 10},  # before start
        {"start": T0 + 10 * 86_400, "end": T0 + 10 * 86_400},  # far from the clock
        {"f_syn_flag_count": "2"},
        {"f_syn_flag_count": float("nan")},
        {"f_extra_feature": 1},
        {"preview": "yes"},
        {"previewed": 1},
        {"preview": True, "previewed": True},
    ],
)
def test_malformed_records_are_rejected(change):
    entry = valid_entry()
    assert flowstream.decode(entry, T0) is not None
    assert flowstream.decode(mutate(entry, **change), T0) is None


def test_malformed_envelopes_are_rejected():
    entry = valid_entry()
    data = json.loads(entry["data"])
    del data["features"]["syn_flag_count"]

    assert flowstream.decode({**entry, "data": json.dumps(data)}, T0) is None
    assert flowstream.decode({**entry, "v": "3"}, T0) is None
    assert flowstream.decode({**entry, "sensor": "../etc"}, T0) is None
    assert flowstream.decode({**entry, "data": "{"}, T0) is None
    assert flowstream.decode({**entry, "data": " " * 20_000}, T0) is None
    assert flowstream.decode({}, T0) is None


def test_preview_flags_round_trip_and_need_protocol_2():
    entry = valid_entry()
    assert entry["v"] == "2"
    preview = mutate(entry, preview=True, previewed=False)

    _, record = flowstream.decode(preview, T0)
    assert record["preview"] is True and record["previewed"] is False
    _, plain = flowstream.decode(mutate(entry, **{}), T0)
    assert plain["preview"] is False
    assert flowstream.decode({**preview, "v": "1"}, T0) is None
    # Finished flows from version 1 senders (e.g. /v2/flows) still decode.
    assert flowstream.decode({**entry, "v": "1"}, T0) is not None


def test_sensor_source_acks_skips_garbage_and_replays_unacked_entries():
    redis, clock = FakeRedis(), Clock()
    first = sensor_source(redis, clock=clock)
    assert isinstance(next(first), Heartbeat)  # creates the group; stream empty

    Sensor(redis, "s1", clock=clock).run(capture(https_session(T0), until=T0 + 2))
    redis._xadd(flowstream.FLOWS_STREAM, {"v": "1", "sensor": "s1", "data": "garbage"})
    assert len(drain(first)) == 1
    assert not redis.groups["engine"]["pending"]

    # An engine that dies after reading but before acknowledging...
    Sensor(redis, "s1", clock=clock).run(capture(https_session(T0 + 5), until=T0 + 7))
    crashed = sensor_source(redis, clock=clock)
    assert next(i for i in crashed if not isinstance(i, Heartbeat))["dst_port"] == 443
    crashed.close()
    assert len(redis.groups["engine"]["pending"]) == 1

    # ... gets the entry again on restart.
    assert len(drain(sensor_source(redis, clock=clock))) == 1
    assert not redis.groups["engine"]["pending"]


def test_sensor_flows_are_classified_end_to_end():
    redis, clock = FakeRedis(), Clock()
    source = sensor_source(redis, clock=clock)
    next(source)
    packets = [p for i in range(20) for p in https_session(T0 + i * 0.2, 50000 + i)]
    Sensor(redis, "laptop", clock=clock).run(capture(packets, until=T0 + 8))

    publisher = MemoryPublisher()
    engine = Engine(Predictor.from_bundle(BUNDLE), publisher, "live")
    engine.run(drain(source))

    assert len(publisher.published) == 20
    for detection in publisher.published:
        jsonschema.validate(detection, SCHEMA)
        assert detection["source"] == "live" and detection["dst_ip"] == S
