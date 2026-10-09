import json
from collections import Counter
from pathlib import Path

import jsonschema
import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from sentinel_ml.inference import Predictor

from sentinel_engine.packets import Packet
from sentinel_engine.pipeline import RULE_BEACON, RULE_FLOOD, RULE_PORTSCAN, Engine
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


def test_botnet_beacons_trigger_the_beaconing_rule(predictor):
    published = simulate(predictor, "botnet").published  # with benign background

    rule = [d for d in published if d["model_version"] == RULE_BEACON]
    bots, c2 = set(ATTACKS["botnet"].sources), ATTACKS["botnet"].target
    assert {d["src_ip"] for d in rule} == bots  # every infected client, no benign one
    assert all((d["dst_ip"], d["dst_port"]) == c2 and d["label"] == "botnet" for d in rule)
    assert len(rule) == len(bots)  # one detection per bot per minute, not one per beacon
    first = rule[0]
    assert first["explanation"][0]["feature"] == "beacon_interval_jitter"
    assert first["features"]["beacon_interval_s"] == pytest.approx(2.0, rel=0.1)
    assert first["risk_score"] > 0
    jsonschema.validate(first, SCHEMA)


def test_benign_background_does_not_look_like_beaconing(predictor):
    publisher = MemoryPublisher()
    sim = Simulator.from_csv(PROFILES, realtime=False, clock=lambda: T0)
    Engine(predictor, publisher, "sim").run(sim.run("normal", loop=True, duration=600))

    assert publisher.published
    assert not [d for d in publisher.published if d["model_version"] == RULE_BEACON]
    assert not [d for d in publisher.published if d["model_version"] == RULE_FLOOD]


def test_traffic_ticks_are_published(predictor):
    events = simulate(predictor, "normal").events

    ticks = [data for kind, data in events if kind == "traffic.tick"]
    assert len(ticks) >= 50
    expected = {"source_id", "flows_per_s", "packets_per_s", "attacks", "attacks_per_s"}
    assert expected | {"max_risk", "active_flows"} <= set(ticks[0])
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


def test_candidate_bundle_detects_a_flood():
    candidate = Predictor.from_bundle(ROOT / "models" / "sentinel-flow" / "2026.10.04")
    assert candidate.weights.tolist() == [1.0] * len(candidate.bundle.classes)  # argmax
    published = simulate(candidate, "ddos").published
    flood = [d for d in published if d["src_ip"].startswith("198.51.100.")]
    assert sum(d["label"] == "ddos" for d in flood) / len(flood) > 0.95


SERVER = "192.168.10.80"


def handshake(ts, client, sport, dport=80, request=300):
    """A complete TCP connection: handshake, request, response, FIN exchange."""
    steps = [
        (0.0, True, "S", 0),
        (0.001, False, "SA", 0),
        (0.002, True, "A", 0),
        (0.003, True, "PA", request),
        (0.004, False, "PA", 1400),
        (0.005, True, "FA", 0),
        (0.006, False, "FA", 0),
        (0.007, True, "A", 0),
    ]
    return [
        Packet(ts + dt, client, SERVER, sport, dport, "tcp", size, flags, 64240)
        if forward
        else Packet(ts + dt, SERVER, client, dport, sport, "tcp", size, flags, 64240)
        for dt, forward, flags, size in steps
    ]


def run_packets(predictor, packets):
    publisher = MemoryPublisher()
    Engine(predictor, publisher, "pcap").run(sorted(packets, key=lambda p: p.ts))
    return publisher.published


def clients(start=T0):
    return [
        p
        for i in range(40)
        for p in handshake(start + i * 0.5, f"192.168.10.{20 + i % 6}", 40000 + i, 443)
    ]


def test_flood_with_full_handshakes_is_caught_by_the_flood_rule(predictor):
    """The model misses floods whose handshakes are captured (it learned
    CIC-IDS2017's mid-stream floods); the flood rule does not."""
    attackers = ["198.51.100.7", "198.51.100.23", "198.51.100.42"]
    flood = [
        p
        for i in range(1200)  # 100 connections/s for 12 s
        for p in handshake(T0 + 2 + i * 0.01, attackers[i % 3], 1024 + i)
    ]
    published = run_packets(predictor, clients() + flood)

    from_attackers = [d for d in published if d["src_ip"] in attackers]
    by_model = [d for d in from_attackers if d["model_version"] != RULE_FLOOD]
    by_rule = [d for d in from_attackers if d["model_version"] == RULE_FLOOD]
    assert all(d["label"] == "benign" for d in by_model)  # what the model alone sees
    assert len(by_rule) / len(from_attackers) > 0.5  # everything after the ramp-up
    assert {(d["label"], d["dst_ip"], d["dst_port"]) for d in by_rule} == {("ddos", SERVER, 80)}
    first = by_rule[0]
    assert first["explanation"][0]["feature"] == "flood_flows_per_s"
    assert first["explanation"][0]["value"] >= 50
    assert first["risk_score"] > 0
    jsonschema.validate(first, SCHEMA)
    legit = [d for d in published if d["src_ip"].startswith("192.168.10.")]
    assert legit and all(d["label"] == "benign" for d in legit)


def test_syn_flood_is_caught_by_the_flood_rule(predictor):
    flood = []
    for i in range(3000):  # 200 SYNs/s for 15 s from spoofed addresses
        src, sport, ts = f"10.{i // 250}.{i % 250}.9", 1024 + i, T0 + 2 + i * 0.005
        flood += [
            Packet(ts, src, SERVER, sport, 80, "tcp", 0, "S", 64240),
            Packet(ts + 0.001, SERVER, src, 80, sport, "tcp", 0, "SA", 65160),
        ]
    published = run_packets(predictor, clients() + flood)

    syns = [d for d in published if d["dst_ip"] == SERVER and d["dst_port"] == 80]
    rule = [d for d in syns if d["model_version"] == RULE_FLOOD]
    assert len(rule) / len(syns) > 0.9
    assert {d["label"] for d in rule} == {"ddos"}
    assert rule[0]["explanation"][0]["feature"] == "flood_half_open_flows_per_s"
    legit = [d for d in published if d["src_ip"].startswith("192.168.10.")]
    assert legit and all(d["label"] == "benign" for d in legit)


def test_open_flood_flows_are_reported_from_previews_once(predictor):
    """Flows stay open for up to 120 s, like CICFlowMeter's, so a SYN flood's
    half-open flows are reported from their previews instead of at the end."""
    publisher = MemoryPublisher()
    engine = Engine(predictor, publisher, "pcap")
    start = T0 + 2
    for i in range(2000):  # 200 SYNs/s for 10 s, no handshake completes
        src, sport, ts = f"10.{i // 250}.{i % 250}.9", 1024 + i, start + i * 0.005
        engine.table.add(Packet(ts, src, SERVER, sport, 80, "tcp", 0, "S", 64240))
    for second in range(1, 17):  # the engine sweeps every second
        engine.handle_flows(engine.table.sweep(start + second), start + second)
        if second == 6:
            early = list(publisher.published)

    # 5 s after the first SYN, with every flow still open, the flood is out.
    assert early and all(d["model_version"] == RULE_FLOOD for d in early)
    assert len(engine.table) == 2000

    engine.handle_flows(engine.table.sweep(start + 130), start + 130)  # flows time out
    flows = Counter((d["src_ip"], d["src_port"]) for d in publisher.published)
    assert max(flows.values()) == 1  # no flow is reported twice
    rule = [d for d in publisher.published if d["model_version"] == RULE_FLOOD]
    assert len(rule) / len(publisher.published) > 0.9  # all but the ramp-up
