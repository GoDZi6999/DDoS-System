"""Minimal packet representation, so the flow builder does not depend on Scapy
(and can be tested with hand-made packets)."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Packet:
    ts: float  # epoch seconds
    src: str
    dst: str
    sport: int
    dport: int
    proto: str  # tcp | udp | icmp | other
    payload: int  # transport payload bytes
    flags: str = ""  # TCP flags as letters: F S R P A U
    window: int | None = None  # TCP window size


@dataclass(frozen=True, slots=True)
class Heartbeat:
    """Advances the engine clock when no packets arrive (live capture)."""

    ts: float


_FLAG_LETTERS = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A", 0x20: "U"}


def from_scapy(pkt) -> Packet | None:
    """Convert a Scapy packet; returns None for non-IP traffic."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None
    ts = float(pkt.time)
    if TCP in pkt:
        tcp = pkt[TCP]
        flags = "".join(letter for bit, letter in _FLAG_LETTERS.items() if int(tcp.flags) & bit)
        return Packet(
            ts, ip.src, ip.dst, tcp.sport, tcp.dport, "tcp", len(tcp.payload), flags, tcp.window
        )
    if UDP in pkt:
        udp = pkt[UDP]
        return Packet(ts, ip.src, ip.dst, udp.sport, udp.dport, "udp", len(udp.payload))
    if ICMP in pkt:
        return Packet(ts, ip.src, ip.dst, 0, 0, "icmp", len(pkt[ICMP].payload))
    return Packet(ts, ip.src, ip.dst, 0, 0, "other", len(ip.payload))
