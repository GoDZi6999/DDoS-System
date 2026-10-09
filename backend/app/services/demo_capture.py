"""A synthetic packet capture for trying the Captures page and for the smoke test.

    python -m app.cli demo-capture demo.pcap

Normal web browsing, then a SYN port scan and an HTTP flood against a web
server. Attackers use documentation addresses (TEST-NET ranges), victims
private ones. Generated with Scapy; it is not real traffic, so it shows the
pipeline working rather than measuring detection quality.

The flood imitates the LOIC HTTP flood in CIC-IDS2017 (the model's training
data) as captured there: connections already open when the capture starts,
tiny client windows, a short request and ~11 KB of response. The current
model recognises it in that shape but not when each connection's handshake
is captured too; see docs/ML_METHODOLOGY.md.
"""

import random
from pathlib import Path

WEB_SERVER = "192.168.10.80"
SCANNER = "203.0.113.66"
CLIENTS = [f"192.168.10.{i}" for i in range(20, 26)]
FLOOD_SOURCES = ["198.51.100.7", "198.51.100.23", "198.51.100.42"]


def build(path: Path, start: float = 1_790_000_000.0, seed: int = 7) -> int:
    """Write the capture to `path`; returns the number of packets."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapWriter

    rng = random.Random(seed)  # noqa: S311 (reproducible synthetic traffic)
    packets = []

    def add(ts, src, dst, sport, dport, flags, payload=b"", window=64240):
        pkt = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, window=window)
        )
        if payload:
            pkt = pkt / payload
        pkt.time = ts
        packets.append(pkt)

    # 0-20 s: ordinary HTTPS sessions to the web server.
    for n in range(40):
        client, port = rng.choice(CLIENTS), 40000 + n
        t = start + rng.uniform(0, 20)
        add(t, client, WEB_SERVER, port, 443, "S")
        add(t + 0.01, WEB_SERVER, client, 443, port, "SA")
        add(t + 0.02, client, WEB_SERVER, port, 443, "A")
        add(
            t + 0.03,
            client,
            WEB_SERVER,
            port,
            443,
            "PA",
            b"\x16\x03\x01" + bytes(rng.randrange(200, 500)),
        )
        for k in range(rng.randrange(3, 8)):
            add(t + 0.05 + k * 0.02, WEB_SERVER, client, 443, port, "PA", bytes(1200))
        add(t + 0.3, client, WEB_SERVER, port, 443, "FA")
        add(t + 0.31, WEB_SERVER, client, 443, port, "FA")
        add(t + 0.32, client, WEB_SERVER, port, 443, "A")

    # 25-27 s: SYN scan of the first 100 ports; closed ports answer with RST.
    for i, port in enumerate(range(1, 101)):
        t = start + 25 + i * 0.02
        add(t, SCANNER, WEB_SERVER, 61000, port, "S")
        if port in (22, 80, 443):
            add(t + 0.005, WEB_SERVER, SCANNER, port, 61000, "SA")
            add(t + 0.01, SCANNER, WEB_SERVER, 61000, port, "R")
        else:
            add(t + 0.005, WEB_SERVER, SCANNER, port, 61000, "RA")

    # 30-36 s: HTTP flood on port 80 from 3 sources (connections already open).
    for i in range(600):
        src, port = rng.choice(FLOOD_SOURCES), 1024 + i
        t = start + 30 + i * 0.01
        add(t, src, WEB_SERVER, port, 80, "A", window=256)
        add(t + 0.001, src, WEB_SERVER, port, 80, "PA", b"GET / HTTP/1.1\r\n\r\n\r\n", window=256)
        for k, size in enumerate((4380, 4380, 2900)):
            add(
                t + 0.002 + k * 0.001,
                WEB_SERVER,
                src,
                80,
                port,
                "PA" if k == 2 else "A",
                bytes(size),
                window=229,
            )
        add(t + 2.7, src, WEB_SERVER, port, 80, "A", bytes(6), window=256)

    packets.sort(key=lambda p: float(p.time))
    with PcapWriter(str(path), linktype=1, sync=False) as writer:
        for pkt in packets:
            writer.write(pkt)
    return len(packets)
