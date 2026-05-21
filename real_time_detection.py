"""
Real-time packet capture and DDoS detection using Scapy.
Extracts the same 15 features used during training, then classifies each flow.
Requires root/sudo for raw packet capture.
"""

import logging
import os
import queue
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Optional

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

SELECTED_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "wrong_fragment", "hot",
    "logged_in", "num_compromised", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
]

# Protocol int encoding matches the notebook LabelEncoder (alphabetical)
PROTOCOL_MAP = {"icmp": 0, "tcp": 1, "udp": 2}
# Simplified flag mapping
FLAG_MAP = {"OTH": 0, "REJ": 1, "RSTO": 2, "RSTOS0": 3, "RSTR": 4,
            "S0": 5, "S1": 6, "S2": 7, "S3": 8, "SF": 9, "SH": 10}
# Top-10 most common services from the dataset (index = encoded value)
SERVICE_MAP = defaultdict(lambda: 0, {
    "aol": 0, "auth": 1, "bgp": 2, "courier": 3, "csnet_ns": 4,
    "ctf": 5, "daytime": 6, "discard": 7, "domain": 8, "domain_u": 9,
    "echo": 10, "eco_i": 11, "ecr_i": 12, "efs": 13, "exec": 14,
    "finger": 15, "ftp": 16, "ftp_data": 17, "gopher": 18, "harvest": 19,
    "hostnames": 20, "http": 21, "http_2784": 22, "http_443": 23,
    "http_8001": 24, "imap4": 25, "IRC": 26, "iso_tsap": 27,
    "klogin": 28, "kshell": 29, "ldap": 30, "link": 31, "login": 32,
    "mtp": 33, "name": 34, "netbios_dgm": 35, "netbios_ns": 36,
    "netbios_ssn": 37, "netstat": 38, "nnsp": 39, "nntp": 40,
    "ntp_u": 41, "other": 42, "pm_dump": 43, "pop_2": 44, "pop_3": 45,
    "printer": 46, "private": 47, "red_i": 48, "remote_job": 49,
    "rje": 50, "shell": 51, "smtp": 52, "sql_net": 53, "ssh": 54,
    "sunrpc": 55, "supdup": 56, "systat": 57, "telnet": 58, "tftp_u": 59,
    "tim_i": 60, "time": 61, "urh_i": 62, "urp_i": 63, "uucp": 64,
    "uucp_path": 65, "vmnet": 66, "whois": 67, "X11": 68, "Z39_50": 69,
})

PORT_SERVICE = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 110: "pop_3", 143: "imap4", 443: "http_443",
    8080: "http", 8443: "http_443",
}

ALERT_QUEUE: queue.Queue = queue.Queue()


class FlowTracker:
    """Maintains per-source connection counters in a sliding window."""

    def __init__(self, window: int = 2):
        self.window = window
        self._flows: dict = defaultdict(lambda: deque())

    def record(self, src_ip: str, ts: float):
        dq = self._flows[src_ip]
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def count(self, src_ip: str, ts: float) -> int:
        self.record(src_ip, ts)
        return len(self._flows[src_ip])


_tracker = FlowTracker()


def extract_features(pkt) -> Optional[pd.DataFrame]:
    """Convert a Scapy packet into the 15-feature vector expected by the model."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        ts = float(pkt.time)
        src = ip.src

        proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip.proto, "other")
        proto_enc = PROTOCOL_MAP.get(proto_name, 1)

        dst_port = 0
        flag_enc = FLAG_MAP["SF"]
        src_bytes = len(pkt)
        dst_bytes = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_port = tcp.dport
            f = tcp.flags
            if f & 0x04:
                flag_enc = FLAG_MAP["RSTO"]
            elif f & 0x14:
                flag_enc = FLAG_MAP["RSTR"]
            elif f & 0x02 and not (f & 0x10):
                flag_enc = FLAG_MAP["S0"]
            else:
                flag_enc = FLAG_MAP["SF"]
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            flag_enc = FLAG_MAP["SF"] if icmp.type == 0 else FLAG_MAP["S0"]

        service = PORT_SERVICE.get(dst_port, "private")
        service_enc = SERVICE_MAP[service]

        cnt = _tracker.count(src, ts)

        row = {
            "duration": 0,
            "protocol_type": proto_enc,
            "service": service_enc,
            "flag": flag_enc,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "wrong_fragment": 0,
            "hot": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "count": cnt,
            "srv_count": cnt,
            "serror_rate": 1.0 if flag_enc == FLAG_MAP["S0"] else 0.0,
            "srv_serror_rate": 1.0 if flag_enc == FLAG_MAP["S0"] else 0.0,
            "rerror_rate": 1.0 if flag_enc == FLAG_MAP["REJ"] else 0.0,
        }
        return pd.DataFrame([row], columns=SELECTED_FEATURES)
    except Exception as exc:
        logger.debug("Feature extraction error: %s", exc)
        return None


class RealTimeDetector:
    def __init__(
        self,
        model_path: str = "models/best_ddos_detector.pkl",
        scaler_path: str = "models/scaler.pkl",
        alert_callback: Optional[Callable] = None,
        threshold: float = 0.5,
    ):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.alert_callback = alert_callback or self._default_alert
        self.threshold = threshold
        self._running = False
        self.stats = {"packets": 0, "attacks": 0, "normal": 0}
        logger.info("RealTimeDetector initialised.")

    def _default_alert(self, info: dict):
        msg = (
            f"[ALERT] {info['timestamp']}  src={info['src_ip']}  "
            f"proto={info['protocol']}  service={info['service']}  "
            f"confidence={info['confidence']:.2%}"
        )
        print(msg)
        logger.warning(msg)
        ALERT_QUEUE.put(info)

    def _handle_packet(self, pkt):
        features = extract_features(pkt)
        if features is None:
            return

        self.stats["packets"] += 1
        X = self.scaler.transform(features)
        proba = self.model.predict_proba(X)[0][1]

        if proba >= self.threshold:
            self.stats["attacks"] += 1
            from scapy.layers.inet import IP
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(
                pkt[IP].proto if pkt.haslayer(IP) else 0, "unknown"
            )
            self.alert_callback({
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "protocol": proto_name,
                "service": "unknown",
                "confidence": float(proba),
                "label": "ATTACK",
            })
        else:
            self.stats["normal"] += 1

    def start(self, interface: str = None, packet_count: int = 0):
        try:
            from scapy.all import sniff
        except ImportError:
            print("Scapy not installed. Run: pip install scapy")
            return

        self._running = True
        print(f"[*] Starting real-time detection on interface: {interface or 'default'}")
        print("[*] Press Ctrl+C to stop.\n")

        kwargs = {"prn": self._handle_packet, "store": False}
        if interface:
            kwargs["iface"] = interface
        if packet_count:
            kwargs["count"] = packet_count

        try:
            from scapy.all import sniff
            sniff(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._print_summary()

    def _print_summary(self):
        s = self.stats
        total = max(s["packets"], 1)
        print(
            f"\n[Summary] Packets={s['packets']}  "
            f"Attacks={s['attacks']} ({s['attacks']/total*100:.1f}%)  "
            f"Normal={s['normal']}"
        )


if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    detector = RealTimeDetector()
    detector.start(interface=iface)
