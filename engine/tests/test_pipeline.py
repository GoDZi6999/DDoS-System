import json
from collections import Counter
from pathlib import Path

import jsonschema
import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from sentinel_ml.inference import Predictor

from sentinel_engine.packets import Packet
from sentinel_engine.pipeline import RULE_PORTSCAN, Engine
from sentinel_engine.publisher import MemoryPublisher
from sentinel_engine.simulator import ATTACKS, SCAN_TARGET, Simulator
from sentinel_engine.sources import pcap_source

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "models" / "sentinel-flow" / "2026.10.03"
PROFILES = ROOT / "data" / "samples" / "flow_profiles.csv"
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "detection.schema.json").read_text())
T0 = 1_790_000_000.0


@pytest.fixture(scope="module")
def predictor():
    return Predictor.from_bundle(BUNDLE)


def simulate(predictor, scenario, publisher=None, **kwargs):
    publisher = publisher or MemoryPublisher()
    engine = Engine(predictor, publisher, "sim")
    sim = Simulator.from_csv(PROFILES, realtime=False, clock=lambda: T0, **kwargs)
    engine.run(sim.run(scenario))
    return publisher


def test_every_detection_matches_the_alert_engine_contract(predictor):
    published = simulate(predictor, "ddos").published

    assert published
    for detection in published[:200] + published[-50:]:
        jsonschema.validate(detection, SCHEMA)


def test_ddos_burst_is_detected_with_rising_risk_and_explanations(predictor):
    published = simulate(predictor, "ddos").published
    attacks = [d for d in published if d["label"] != "benign"]
    ddos = [d for d in attacks if d["label"] == "ddos"]

    assert len(ddos) / len([d for d in published if d["src_ip"].startswith("198.51.100.")]) > 0.95
    assert all(d["dst_ip"] == ATTACKS["ddos"].target[0] for d in ddos)
    # Floods are explained on a sample (see test_explanations_are_budgeted).
    assert ddos[0]["explanation"]
    assert 0 < sum(bool(d["explanation"]) for d in ddos) < len(ddos)
    assert set(ddos[0]["risk_components"]) == {
        "ml_confidence",
        "traffic_anomaly",
        "attack_severity",
        "source_reputation",
    }
    first, last = ddos[0]["risk_score"], max(d["risk_score"] for d in ddos[-50:])
    assert last > first  # the flood ramps up, so anomaly (and risk) grows
    assert last >= 81  # CRITICAL by the end
    benign = [d for d in published if d["label"] == "benign"]
    assert benign and all(d["risk_score"] == 0 for d in benign)


def test_port_scan_probes_go_through_the_flow_builder_and_trigger_the_rule(predictor):
    published = simulate(predictor, "portscan", benign_rate=0).published

    rule = [d for d in published if d["model_version"] == RULE_PORTSCAN]
    assert rule
    assert rule[0]["label"] == "portscan" and rule[0]["dst_ip"] == SCAN_TARGET
    assert rule[0]["features"]["window_distinct_ports_src_to_dst"] >= 20
    assert rule[0]["explanation"][0]["feature"] == "window_distinct_ports_src_to_dst"
    # One rule detection per scanner/target per window, not one per probe.
    assert len(rule) <= 30 / 10 + 1
    probe_flows = [d for d in published if d["model_version"] != RULE_PORTSCAN]
    assert all(d["packet_count"] == 2 for d in probe_flows)  # SYN + RST


def test_traffic_ticks_are_published(predictor):
    events = simulate(predictor, "normal").events

    ticks = [data for kind, data in events if kind == "traffic.tick"]
    assert len(ticks) >= 50
    expected = {"flows_per_s", "packets_per_s", "attacks", "attacks_per_s", "max_risk"}
    assert expected | {"active_flows"} <= set(ticks[0])
    assert 5 < sum(t["flows_per_s"] for t in ticks) / len(ticks) < 30  # ~15 benign flows/s


def test_risk_weights_follow_the_published_settings(predictor):
    weights = {
        "ml_confidence": 0.0,
        "traffic_anomaly": 0.0,
        "attack_severity": 1.0,
        "source_reputation": 0.0,
    }
    publisher = MemoryPublisher(config={"risk_weights": weights})

    published = simulate(predictor, "bruteforce", publisher=publisher, benign_rate=0).published

    brute = [d for d in published if d["label"] == "bruteforce"]
    assert brute and all(d["risk_score"] == 65 for d in brute)  # severity only


def test_demo_scenario_covers_every_attack(predictor):
    published = simulate(predictor, "demo").published

    labels = Counter(d["label"] for d in published)
    for attack in ("ddos", "dos", "bruteforce", "webattack", "botnet", "portscan"):
        assert labels[attack] > 0, attack


def test_pcap_replay_builds_flows_from_real_packets(predictor, tmp_path):
    client, server = "10.0.0.1", "10.0.0.2"
    packets = []
    for i, (src, dst, sport, dport, flags) in enumerate(
        [
            (client, server, 40000, 80, "S"),
            (server, client, 80, 40000, "SA"),
            (client, server, 40000, 80, "A"),
            (client, server, 40000, 80, "FA"),
            (server, client, 80, 40000, "FA"),
            (client, server, 40000, 80, "A"),
        ]
    ):
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, window=8192)
        pkt.time = 1_500_000_000 + i * 0.01  # a 2017-era capture
        packets.append(pkt)
    path = tmp_path / "exchange.pcap"
    wrpcap(str(path), packets)

    replayed = list(pcap_source(path, realtime=False))
    publisher = MemoryPublisher()
    Engine(predictor, publisher, "pcap").run(replayed)

    assert all(isinstance(p, Packet) for p in replayed) and len(replayed) == 6
    assert replayed[0].ts > 1_700_000_000  # retimed to "now"
    assert replayed[1].flags == "SA" and replayed[0].window == 8192
    assert len(publisher.published) == 1
    detection = publisher.published[0]
    assert detection["source"] == "pcap"
    assert detection["packet_count"] == 6
    assert detection["features"]["syn_flag_count"] == 2
    jsonschema.validate(detection, SCHEMA)


def test_explanations_are_budgeted_per_target_and_second(predictor):
    engine = Engine(predictor, MemoryPublisher(), "sim", explain_per_target_s=5)
    sim = Simulator.from_csv(PROFILES, realtime=False)

    def flood(target, count):
        return [sim._flow("ddos", f"198.51.100.{i % 200}", target, 80, T0) for i in range(count)]

    def explained(detections, target):
        return sum(
            1
            for d in detections
            if d["dst_ip"] == target and d["label"] != "benign" and d["explanation"]
        )

    first = engine.handle_flows(flood("10.20.0.10", 40) + flood("10.20.0.11", 40), T0)
    assert explained(first, "10.20.0.10") == 5
    assert explained(first, "10.20.0.11") == 5  # each target has its own budget
    assert explained(engine.handle_flows(flood("10.20.0.10", 40), T0 + 0.5), "10.20.0.10") == 0
    assert explained(engine.handle_flows(flood("10.20.0.10", 40), T0 + 1), "10.20.0.10") == 5
