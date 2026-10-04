"""Engine inputs: PCAP replay and live capture (both via Scapy), and flow
records shipped by remote capture sensors (Redis stream)."""

import logging
import queue
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from redis.exceptions import RedisError

from sentinel_engine.flowstream import ENGINE_GROUP, FLOWS_STREAM, decode
from sentinel_engine.packets import Heartbeat, Packet, from_scapy

logger = logging.getLogger(__name__)


def pcap_source(
    path: Path, speed: float = 1.0, retime: bool = True, realtime: bool = True
) -> Iterator[Packet]:
    """Replay a capture. `speed` > 1 replays faster; `retime` shifts timestamps
    so the capture starts now (old captures would otherwise fall outside the
    dashboard's time windows)."""
    import scapy.layers.all  # noqa: F401  (link-layer decoders, e.g. Ethernet)
    from scapy.utils import PcapReader

    offset = None
    wall_start = time.time()
    with PcapReader(str(path)) as reader:
        for raw in reader:
            packet = from_scapy(raw)
            if packet is None:
                continue
            if offset is None:
                offset = (wall_start - packet.ts) if retime else 0.0
                first_ts = packet.ts
            if realtime and speed > 0:
                delay = (packet.ts - first_ts) / speed - (time.time() - wall_start)
                if delay > 0:
                    time.sleep(delay)
            if offset:
                packet = Packet(
                    packet.ts + offset,
                    packet.src,
                    packet.dst,
                    packet.sport,
                    packet.dport,
                    packet.proto,
                    packet.payload,
                    packet.flags,
                    packet.window,
                )
            yield packet


def live_source(
    interface: str | None,
    bpf_filter: str | None = None,
    on_drop: Callable[[int], None] | None = None,
) -> Iterator:
    """Capture packets (read-only; needs CAP_NET_RAW). Yields a Heartbeat each
    second without traffic so flows still time out. `on_drop` counts packets
    lost to a full queue (the consumer fell behind)."""
    import scapy.layers.all  # noqa: F401  (link-layer decoders, e.g. Ethernet)
    from scapy.all import AsyncSniffer  # loads the platform providers (Npcap)

    packets: queue.Queue = queue.Queue(maxsize=100_000)

    def enqueue(raw) -> None:
        packet = from_scapy(raw)
        if packet is not None:
            try:
                packets.put_nowait(packet)
            except queue.Full:
                if on_drop is not None:
                    on_drop(1)
                logger.warning("Capture queue full; dropping packets")

    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=enqueue, store=False)
    sniffer.start()
    logger.info("Capturing on %s", interface or "default interface")
    try:
        while True:
            try:
                yield packets.get(timeout=1.0)
            except queue.Empty:
                yield Heartbeat(time.time())
    finally:
        sniffer.stop()


def sensor_source(
    client,
    group: str = ENGINE_GROUP,
    consumer: str = "engine",
    block_ms: int = 1000,
    count: int = 500,
    clock: Callable[[], float] = time.time,
    stop: Callable[[], bool] = lambda: False,
) -> Iterator:
    """Flow records from capture sensors (stream `sentinel:flows`).

    Reads through a consumer group, so several engine replicas can share the
    load and a restarted engine resumes where it stopped: entries it had read
    but not acknowledged are replayed first (at-least-once delivery). Malformed
    entries are acknowledged and dropped. Yields a Heartbeat whenever the
    stream is idle, so the engine's windows and ticks keep moving.
    """
    try:
        client.xgroup_create(FLOWS_STREAM, group, id="$", mkstream=True)
    except RedisError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    logger.info("Reading sensor flows from %s as %s/%s", FLOWS_STREAM, group, consumer)
    cursor = "0"  # first our own unacknowledged entries, then new ones
    rejected = 0
    while not stop():
        try:
            response = client.xreadgroup(
                group, consumer, {FLOWS_STREAM: cursor}, count=count, block=block_ms
            )
        except RedisError:
            logger.warning("Could not read sensor flows; retrying", exc_info=True)
            time.sleep(1.0)
            yield Heartbeat(clock())
            continue
        entries = [entry for _stream, items in response or [] for entry in items]
        if not entries:
            cursor = ">"
            yield Heartbeat(clock())
            continue
        for _entry_id, fields in entries:
            decoded = decode(fields, clock()) if fields else None
            if decoded is None:
                rejected += 1
                if rejected in (1, 10, 100) or rejected % 1000 == 0:
                    logger.warning("Dropped %d malformed sensor entries so far", rejected)
                continue
            yield decoded[1]
        client.xack(FLOWS_STREAM, group, *[entry_id for entry_id, _ in entries])
