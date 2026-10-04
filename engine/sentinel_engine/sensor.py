"""Capture sensor: sniff packets on the host whose traffic matters, build flows
there and ship the flow records to the stack, where `run --source sensor`
classifies them.

    python -m sentinel_engine.sensor --list-interfaces
    python -m sentinel_engine.sensor --interface "Wi-Fi" --name laptop

Capture stays read-only. Only flow statistics leave the host (addresses,
ports, counts, timings), never payloads. The sensor needs Scapy and redis-py
only (engine/requirements-sensor.txt), not the ML stack, so it also runs on
hosts where the engine cannot, e.g. Windows next to Docker Desktop, whose
containers cannot see the host's network adapters.

Environment: SENSOR_REDIS_URL, e.g. redis://sensor:<password>@localhost:6379/0
(the stack's restricted `sensor` account; see docker-compose.sensor.yml).
"""

import argparse
import logging
import os
import platform
import re
import socket
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable

from sentinel_engine.flows import FlowTable
from sentinel_engine.flowstream import (
    FLOWS_MAXLEN,
    FLOWS_STREAM,
    PROTOCOL_VERSION,
    SENSOR_KEY_TTL_S,
    SENSOR_NAME,
    encode,
    sensor_key,
)
from sentinel_engine.packets import Heartbeat, Packet

logger = logging.getLogger("sentinel_engine.sensor")

SWEEP_S = 1.0
HEARTBEAT_S = 5.0
BUFFER_MAX = 50_000  # flows kept while the stack is unreachable
BATCH = 500
RETRY_MAX_S = 30.0


def default_name() -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname()).strip("-.")[:64]
    return name if name and SENSOR_NAME.match(name) else "sensor"


class Sensor:
    """Flow building, buffering and shipping. `run()` takes any packet source,
    so tests drive it with hand-made packets and a fake Redis client."""

    def __init__(
        self,
        client,
        name: str,
        interface: str | None = None,
        bpf_filter: str | None = None,
        clock: Callable[[], float] = time.time,
        buffer_max: int = BUFFER_MAX,
    ) -> None:
        if not SENSOR_NAME.match(name):
            raise ValueError(f"Invalid sensor name {name!r}: use letters, digits, . _ - (max 64)")
        self.client = client
        self.name = name
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.clock = clock
        self.table = FlowTable()
        self.buffer: deque[dict] = deque(maxlen=buffer_max)
        self.started_at = clock()
        self.packets = 0
        self.flows_sent = 0
        self.flows_dropped = 0  # buffer overflow while the stack was unreachable
        self.capture_drops = 0  # capture queue overflow (set by the source)
        self.connected = False
        self._retry_at = 0.0
        self._retry_s = 1.0
        self._last_beat: tuple[float, int] | None = None

    # --- shipping -----------------------------------------------------------

    def _queue(self, records: list[dict]) -> None:
        overflow = len(self.buffer) + len(records) - (self.buffer.maxlen or 0)
        if overflow > 0:
            self.flows_dropped += overflow
        self.buffer.extend(records)

    def flush(self) -> None:
        """Send buffered flows; on failure keep them and back off."""
        if not self.buffer or self.clock() < self._retry_at:
            return
        try:
            while self.buffer:
                batch = [self.buffer[i] for i in range(min(BATCH, len(self.buffer)))]
                pipe = self.client.pipeline(transaction=False)
                for record in batch:
                    pipe.xadd(
                        FLOWS_STREAM,
                        encode(record, self.name),
                        maxlen=FLOWS_MAXLEN,
                        approximate=True,
                    )
                pipe.execute()
                for _ in batch:
                    self.buffer.popleft()
                self.flows_sent += len(batch)
        except Exception as exc:  # redis errors, DNS, refused connections ...
            self._failed(exc)
        else:
            self._connected()

    def heartbeat(self, state: str = "running") -> None:
        now = self.clock()
        rate = 0.0
        if self._last_beat is not None and now > self._last_beat[0]:
            rate = (self.packets - self._last_beat[1]) / (now - self._last_beat[0])
        self._last_beat = (now, self.packets)
        status = {
            "name": self.name,
            "hostname": socket.gethostname()[:128],
            "platform": f"{platform.system()} {platform.release()}"[:64],
            "interface": (self.interface or "default")[:128],
            "filter": (self.bpf_filter or "")[:256],
            "protocol": PROTOCOL_VERSION,
            "state": state,
            "started_at": self.started_at,
            "last_seen": now,
            "packets": self.packets,
            "packets_per_s": round(rate, 2),
            "flows_sent": self.flows_sent,
            "flows_buffered": len(self.buffer),
            "flows_dropped": self.flows_dropped,
            "capture_drops": self.capture_drops,
            "active_flows": len(self.table),
        }
        if self.clock() < self._retry_at:
            return
        try:
            pipe = self.client.pipeline(transaction=False)
            pipe.hset(sensor_key(self.name), mapping=status)
            pipe.expire(sensor_key(self.name), SENSOR_KEY_TTL_S)
            pipe.execute()
        except Exception as exc:
            self._failed(exc)
        else:
            self._connected()

    def _connected(self) -> None:
        if not self.connected:
            logger.info("Connected to the stack; shipping flows as %r", self.name)
        self.connected = True
        self._retry_s = 1.0

    def _failed(self, exc: Exception) -> None:
        if self.connected or self._retry_s == 1.0:
            logger.warning(
                "Stack unreachable (%s); buffering flows (%d held) and retrying",
                exc,
                len(self.buffer),
            )
        self.connected = False
        self._retry_at = self.clock() + self._retry_s
        self._retry_s = min(self._retry_s * 2, RETRY_MAX_S)

    # --- main loop ------------------------------------------------------------

    def run(self, source: Iterable) -> None:
        last_sweep = last_beat = None
        try:
            for item in source:
                if isinstance(item, Packet):
                    self.table.add(item)
                    self.packets += 1
                    now = item.ts
                elif isinstance(item, Heartbeat):
                    now = item.ts
                else:
                    continue
                if last_sweep is None:
                    last_sweep = now
                if now - last_sweep >= SWEEP_S:
                    self._queue(self.table.sweep(now))
                    self.flush()
                    last_sweep = now
                wall = self.clock()
                if last_beat is None or wall - last_beat >= HEARTBEAT_S:
                    self.heartbeat()
                    last_beat = wall
        finally:
            self._queue(self.table.flush())
            self._retry_at = 0.0
            self.flush()
            self._retry_at = 0.0
            self.heartbeat("stopped")


def list_interfaces() -> None:
    from scapy.all import get_working_ifaces  # loads the platform providers (Npcap)

    for iface in get_working_ifaces():
        addresses = ", ".join(a for a in (iface.ip, getattr(iface, "mac", "")) if a)
        print(f"{iface.name:40} {iface.description or ''}  {addresses}".rstrip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel_engine.sensor",
        description="Capture this host's traffic and ship flow records to SentinelAI.",
    )
    parser.add_argument("--interface", help="adapter to capture on (see --list-interfaces)")
    parser.add_argument("--filter", help='BPF capture filter, e.g. "tcp or udp"')
    parser.add_argument("--name", default=default_name(), help="sensor name (default: hostname)")
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("SENSOR_REDIS_URL") or os.environ.get("REDIS_URL"),
        help="stack Redis URL (default: $SENSOR_REDIS_URL)",
    )
    parser.add_argument("--list-interfaces", action="store_true", help="list adapters and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.list_interfaces:
        list_interfaces()
        return 0
    if not args.redis_url:
        parser.error("set SENSOR_REDIS_URL or pass --redis-url")
    if not SENSOR_NAME.match(args.name):
        parser.error("--name: letters, digits, . _ - only (max 64)")

    import redis

    from sentinel_engine.sources import live_source

    client = redis.Redis.from_url(args.redis_url, socket_connect_timeout=5, socket_timeout=10)
    sensor = Sensor(client, args.name, args.interface, args.filter)

    def dropped(count: int) -> None:
        sensor.capture_drops += count

    logger.info("Sensor %r starting on %s", args.name, args.interface or "default interface")
    try:
        sensor.run(live_source(args.interface, args.filter, on_drop=dropped))
    except KeyboardInterrupt:
        logger.info("Stopped")
    except PermissionError:
        logger.error("Capture needs administrator/root rights (or CAP_NET_RAW) on this host")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
