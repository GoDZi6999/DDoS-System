"""Packet sources: PCAP replay and live capture (both via Scapy)."""

import logging
import queue
import time
from collections.abc import Iterator
from pathlib import Path

from argus_engine.packets import Heartbeat, Packet, from_scapy

logger = logging.getLogger(__name__)


def pcap_source(
    path: Path, speed: float = 1.0, retime: bool = True, realtime: bool = True
) -> Iterator[Packet]:
    """Replay a capture. `speed` > 1 replays faster; `retime` shifts timestamps
    so the capture starts now (old captures would otherwise fall outside the
    dashboard's time windows)."""
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


def live_source(interface: str | None, bpf_filter: str | None = None) -> Iterator:
    """Capture packets (read-only; needs CAP_NET_RAW). Yields a Heartbeat each
    second without traffic so flows still time out."""
    from scapy.sendrecv import AsyncSniffer

    packets: queue.Queue = queue.Queue(maxsize=100_000)

    def enqueue(raw) -> None:
        packet = from_scapy(raw)
        if packet is not None:
            try:
                packets.put_nowait(packet)
            except queue.Full:
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
