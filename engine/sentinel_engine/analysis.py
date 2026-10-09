"""On-demand analysis: classify a packet capture or a batch of flow records
with the live engine's pipeline (flow builder, classifier, cross-flow rules,
risk score), without Redis. Used by `python -m sentinel_engine analyze` and
by the analysis API (api.py).

Captures from Wireshark (.pcapng), dumpcap or tcpdump (.pcap) are read as
they are, with their original timestamps. Every detection carries a
Wireshark display filter that selects the packets behind it, so an analyst
can open the same capture in Wireshark and see exactly what was flagged.
"""

import ipaddress
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_ml.inference import Predictor

from sentinel_engine.packets import Packet
from sentinel_engine.pipeline import Engine
from sentinel_engine.publisher import MemoryPublisher

BENIGN = "benign"

# Risk bands, as in the API's alerts (backend/app/models/enums.py).
SEVERITIES = ((81, "critical"), (61, "high"), (31, "medium"), (0, "low"))

# Advisory only: the analysis never blocks anything on its own.
ACTIONS = {
    "ddos": "Apply rate limiting or upstream filtering for {dst}; engage the ISP or "
    "scrubbing provider if the volume keeps rising.",
    "dos": "Rate-limit {src} and check which resource on {dst} is being exhausted.",
    "portscan": "Review which services on {dst} are exposed; block {src} at the perimeter "
    "once the scan is confirmed as unauthorised.",
    "bruteforce": "Block {src}, check {dst} for successful logins, and enforce lockout or "
    "key-only authentication.",
    "webattack": "Review the application logs on {dst} for {src}; put a WAF rule in front "
    "of the targeted endpoint.",
    "botnet": "Isolate {src} for forensic review and look for other hosts contacting {dst}.",
}


def severity(risk: int) -> str:
    return next(name for floor, name in SEVERITIES if risk >= floor)


def _address_filter(field_v4: str, field_v6: str, address: str) -> str:
    version = ipaddress.ip_address(address).version
    return f"{field_v4 if version == 4 else field_v6} == {address}"


def wireshark_filter(detection: dict) -> str:
    """Display filter for the packets behind a detection (both directions).
    Rule detections have no source port (and port scans no destination
    port), so those parts are left out."""
    src, dst = detection["src_ip"], detection["dst_ip"]
    parts = [_address_filter("ip.addr", "ipv6.addr", ip) for ip in dict.fromkeys((src, dst))]
    protocol = detection["protocol"]
    if protocol in ("tcp", "udp"):
        ports = [p for p in dict.fromkeys((detection["src_port"], detection["dst_port"])) if p]
        parts += [f"{protocol}.port == {p}" for p in ports] or [protocol]
    elif protocol == "icmp":
        parts.append("(icmp || icmpv6)")
    return " && ".join(parts)


def enrich(detection: dict) -> dict:
    """Adds what a person or another system needs to act on a detection."""
    label = detection["label"]
    enriched = {**detection, "wireshark_filter": wireshark_filter(detection)}
    if label != BENIGN:
        enriched["severity"] = severity(int(detection["risk_score"]))
        enriched["recommended_action"] = ACTIONS.get(
            label, "Investigate traffic between {src} and {dst}."
        ).format(src=detection["src_ip"], dst=detection["dst_ip"])
    return enriched


@dataclass
class Report:
    model_version: str
    flows: int
    detections: list[dict] = field(default_factory=list)  # enriched, in time order

    @property
    def attacks(self) -> list[dict]:
        return [d for d in self.detections if d["label"] != BENIGN]

    def summary(self, top: int = 10) -> dict:
        attacks = self.attacks
        by_source: dict[str, dict] = {}
        for d in attacks:
            entry = by_source.setdefault(
                d["src_ip"], {"src_ip": d["src_ip"], "detections": 0, "max_risk": 0, "labels": []}
            )
            entry["detections"] += 1
            entry["max_risk"] = max(entry["max_risk"], int(d["risk_score"]))
            if d["label"] not in entry["labels"]:
                entry["labels"].append(d["label"])
        timestamps = [d["ts"] for d in self.detections]
        return {
            "model_version": self.model_version,
            "flows": self.flows,
            "attack_detections": len(attacks),
            "by_label": dict(Counter(d["label"] for d in attacks).most_common()),
            "by_severity": dict(Counter(d["severity"] for d in attacks).most_common()),
            "max_risk": max((int(d["risk_score"]) for d in attacks), default=0),
            "top_sources": sorted(
                by_source.values(), key=lambda e: (-e["max_risk"], -e["detections"])
            )[:top],
            "top_targets": [
                {"dst_ip": ip, "detections": n}
                for ip, n in Counter(d["dst_ip"] for d in attacks).most_common(top)
            ],
            "first_ts": min(timestamps, default=None),
            "last_ts": max(timestamps, default=None),
        }


class _IndexedEngine(Engine):
    """Copies a record's position in the caller's batch onto its detection."""

    def _detection(self, record: dict, prediction, risk: int, components: dict) -> dict:
        detection = super()._detection(record, prediction, risk, components)
        if "index" in record:
            detection["flow_index"] = record["index"]
        return detection


def _run(predictor: Predictor, source: Iterable, kind: str) -> Report:
    publisher = MemoryPublisher()
    engine = _IndexedEngine(predictor, publisher, kind)
    engine.run(source)
    detections = [enrich(d) for d in publisher.published]
    flow_count = sum(1 for d in detections if d["model_version"] == engine.model_version)
    return Report(engine.model_version, flow_count, detections)


def analyze_packets(predictor: Predictor, packets: Iterable[Packet]) -> Report:
    """Packets (in capture order) -> flows -> detections."""
    return _run(predictor, packets, "pcap")


def analyze_capture(predictor: Predictor, path: Path) -> Report:
    """A .pcap/.pcapng file from Wireshark, dumpcap or tcpdump, original timestamps kept."""
    from sentinel_engine.sources import pcap_source

    return analyze_packets(predictor, pcap_source(path, retime=False, realtime=False))


def analyze_records(predictor: Predictor, records: list[dict]) -> Report:
    """Validated flow records (flowstream.parse_record) -> one detection per
    record (its `flow_index` is the record's position in `records`), plus any
    rule detections across them."""
    indexed = sorted(
        ({**record, "index": i} for i, record in enumerate(records)), key=lambda r: r["end"]
    )
    report = _run(predictor, indexed, "live")
    report.detections.sort(key=lambda d: (d.get("flow_index") is None, d.get("flow_index", 0)))
    return report


def print_report(report: Report, as_json: bool = False, include_benign: bool = False) -> None:
    """The CLI's output: a readable summary, or the full report as JSON."""
    if as_json:
        import json

        detections = report.detections if include_benign else report.attacks
        print(json.dumps({"summary": report.summary(), "detections": detections}, indent=2))
        return
    s = report.summary()
    print(
        f"Model {s['model_version']}: {s['flows']:,} flows, "
        f"{s['attack_detections']:,} attack detections"
    )
    if not s["attack_detections"]:
        print("No attacks detected.")
        return
    print(f"Time span: {s['first_ts']} to {s['last_ts']}; max risk {s['max_risk']}")
    print("By type:     " + ", ".join(f"{k} {v}" for k, v in s["by_label"].items()))
    print("By severity: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items()))
    print("\nTop sources:")
    for src in s["top_sources"]:
        print(
            f"  {src['src_ip']:<40} {src['detections']:>6} detections, max risk "
            f"{src['max_risk']:>3}  {', '.join(src['labels'])}"
        )
    print("\nHighest-risk detections (paste the filter into Wireshark's display filter bar):")
    for d in sorted(report.attacks, key=lambda d: -int(d["risk_score"]))[:10]:
        print(
            f"  {d['ts']}  {d['label']:<10} risk {d['risk_score']:>3} ({d['severity']})  "
            f"{d['src_ip']} -> {d['dst_ip']}:{d['dst_port']}"
        )
        print(f"      {d['wireshark_filter']}")
