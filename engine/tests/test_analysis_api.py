from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapNgWriter
from sentinel_ml.inference import Predictor

from sentinel_engine import analysis, api
from sentinel_engine.__main__ import main
from sentinel_engine.flowstream import FEATURE_KEYS
from sentinel_engine.simulator import ATTACKS, Simulator

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "models" / "sentinel-flow" / "2026.10.03"
PROFILES = ROOT / "data" / "samples" / "flow_profiles.csv"
T0 = 1_500_000_000.0  # captures keep their original (here 2017-era) timestamps
ATTACKER, TARGET, CLIENT, SERVER = "203.0.113.99", "10.20.0.13", "10.0.0.1", "10.0.0.2"


@pytest.fixture(scope="module")
def predictor():
    return Predictor.from_bundle(BUNDLE)


def write_capture(path: Path) -> Path:
    """A Wireshark-format (.pcapng) capture: one normal HTTP exchange and a
    SYN scan of 40 ports answered by resets."""
    packets = []
    for i, (src, dst, sport, dport, flags) in enumerate(
        [
            (CLIENT, SERVER, 40000, 80, "S"),
            (SERVER, CLIENT, 80, 40000, "SA"),
            (CLIENT, SERVER, 40000, 80, "A"),
            (CLIENT, SERVER, 40000, 80, "FA"),
            (SERVER, CLIENT, 80, 40000, "FA"),
            (CLIENT, SERVER, 40000, 80, "A"),
        ]
    ):
        packets.append(
            (T0 + i * 0.01, IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags))
        )
    for port in range(1, 41):
        t = T0 + 1 + port * 0.05
        packets.append(
            (t, IP(src=ATTACKER, dst=TARGET) / TCP(sport=50000 + port, dport=port, flags="S"))
        )
        packets.append(
            (
                t + 0.0004,
                IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=50000 + port, flags="RA"),
            )
        )
    writer = PcapNgWriter(str(path))
    for ts, packet in packets:
        packet.time = ts
        writer.write(packet)
    writer.close()
    return path


def test_wireshark_filters_select_the_packets_behind_a_detection():
    flow = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80}
    assert (
        analysis.wireshark_filter({**flow, "protocol": "tcp"})
        == "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 40000 && tcp.port == 80"
    )
    scan = {**flow, "src_port": 0, "dst_port": 0, "protocol": "tcp"}  # port-scan rule
    assert analysis.wireshark_filter(scan) == "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp"
    beacon = {**flow, "src_port": 0, "dst_port": 8080, "protocol": "tcp"}  # beaconing rule
    assert analysis.wireshark_filter(beacon).endswith("&& tcp.port == 8080")
    v6 = {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "src_port": 0, "dst_port": 0}
    assert (
        analysis.wireshark_filter({**v6, "protocol": "icmp"})
        == "ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2 && (icmp || icmpv6)"
    )


def test_a_wireshark_capture_is_analysed_with_original_timestamps(predictor, tmp_path):
    report = analysis.analyze_capture(predictor, write_capture(tmp_path / "scan.pcapng"))

    summary = report.summary()
    assert summary["flows"] == 41  # the HTTP exchange and 40 probe flows
    scans = [d for d in report.attacks if d["model_version"] == "rule:portscan-v1"]
    assert scans and scans[0]["src_ip"] == ATTACKER and scans[0]["dst_ip"] == TARGET
    assert scans[0]["ts"].startswith("2017-07-14")  # not shifted to "now"
    assert scans[0]["wireshark_filter"] == f"ip.addr == {ATTACKER} && ip.addr == {TARGET} && tcp"
    assert scans[0]["severity"] in {"low", "medium", "high", "critical"}
    assert ATTACKER in scans[0]["recommended_action"]
    assert summary["top_sources"][0]["src_ip"] == ATTACKER
    assert "portscan" in summary["by_label"]


def test_cli_prints_a_report_with_wireshark_filters(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MODEL_BUNDLE", str(BUNDLE))
    assert main(["analyze", "--pcap", str(write_capture(tmp_path / "scan.pcapng"))]) == 0

    out = capsys.readouterr().out
    assert "41 flows" in out and "Top sources:" in out and ATTACKER in out
    assert f"ip.addr == {ATTACKER} && ip.addr == {TARGET} && tcp" in out


def test_api_key_command_prints_a_key_and_its_hash(capsys):
    assert main(["api-key", "--name", "acme"]) == 0
    lines = capsys.readouterr().out.splitlines()
    key = lines[0].rsplit(" ", 1)[1]
    assert lines[1].endswith(f"acme:{api.hash_key(key)}")
    assert api.parse_keys(lines[1].rsplit(" ", 1)[1]) == {api.hash_key(key): "acme"}
    with pytest.raises(ValueError, match="expected name:sha256hex"):
        api.parse_keys("acme:not-a-hash")


KEY = "argus_test-key"


@pytest.fixture(scope="module")
def client(predictor):
    app = api.create_app(predictor, {api.hash_key(KEY): "acme"}, max_upload_bytes=200_000)
    return TestClient(app)


def flows(n_benign: int = 5, n_ddos: int = 5) -> list[dict]:
    sim = Simulator.from_csv(PROFILES, realtime=False)
    target, port = ATTACKS["ddos"].target
    benign = [
        sim._flow("benign", "10.10.0.20", "10.20.0.11", 8080, T0 + i) for i in range(n_benign)
    ]
    ddos = [sim._flow("ddos", f"198.51.100.{i}", target, port, T0 + 0.5) for i in range(n_ddos)]
    # The sensors' wire format: the classifier derives the two rates itself.
    return [
        {**f, "features": {k: v for k, v in f["features"].items() if k in FEATURE_KEYS}}
        for f in benign + ddos
    ]


def test_api_needs_a_valid_key(client):
    assert client.get("/health").json()["model_version"] == "sentinel-flow-2026.10.03"
    assert client.post("/v1/analyze", json={"flows": flows()}).status_code == 401
    wrong = client.post("/v1/analyze", json={"flows": flows()}, headers={"X-API-Key": "nope"})
    assert wrong.status_code == 401
    with pytest.raises(ValueError, match="refusing to run without auth"):
        api.create_app(None, {})


def test_api_returns_one_verdict_per_flow_in_input_order(client):
    batch = flows()
    response = client.post("/v1/analyze", json={"flows": batch}, headers={"X-API-Key": KEY})

    assert response.status_code == 200
    body = response.json()
    assert body["tenant"] == "acme"
    per_flow = [d for d in body["detections"] if d.get("flow_index") is not None]
    assert [d["flow_index"] for d in per_flow] == list(range(len(batch)))
    assert [d["src_ip"] for d in per_flow] == [f["src_ip"] for f in batch]
    assert all(d["label"] == "ddos" for d in per_flow[5:])
    assert all("wireshark_filter" in d for d in per_flow)
    assert per_flow[5]["severity"] and per_flow[5]["recommended_action"]
    assert body["summary"]["flows"] == len(batch)
    assert body["summary"]["by_label"]["ddos"] == 5


def test_api_rejects_malformed_flows_and_says_which(client):
    batch = flows()
    batch[2] = {**batch[2], "src_ip": "not-an-ip"}
    del batch[4]["features"]
    response = client.post("/v1/analyze", json={"flows": batch}, headers={"X-API-Key": KEY})

    assert response.status_code == 422
    assert response.json()["detail"]["flow_indexes"] == [2, 4]


def test_api_analyses_an_uploaded_capture(client, tmp_path):
    capture = write_capture(tmp_path / "scan.pcapng").read_bytes()
    response = client.post(
        "/v1/analyze/pcap",
        files={"capture": ("scan.pcapng", capture, "application/octet-stream")},
        headers={"X-API-Key": KEY},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["flows"] == 41 and not body["truncated"]
    assert all(d["label"] != "benign" for d in body["detections"])  # attacks only by default
    assert any(d["model_version"] == "rule:portscan-v1" for d in body["detections"])


def test_api_rejects_non_captures_and_oversized_uploads(client):
    headers = {"X-API-Key": KEY}
    text = client.post("/v1/analyze/pcap", files={"capture": ("a.txt", b"hello")}, headers=headers)
    assert text.status_code == 422
    big = b"\x0a\x0d\x0d\x0a" + b"\0" * 300_000
    assert (
        client.post(
            "/v1/analyze/pcap", files={"capture": ("big", big)}, headers=headers
        ).status_code
        == 413
    )


def test_rate_limit_is_per_key_and_says_when_to_retry():
    now = [0.0]
    limiter = api.RateLimiter(per_minute=2, clock=lambda: now[0])

    assert limiter.retry_after("acme") == 0
    assert limiter.retry_after("acme") == 0
    assert limiter.retry_after("acme") > 0
    assert limiter.retry_after("other") == 0  # each tenant has its own budget
    now[0] = 61.0
    assert limiter.retry_after("acme") == 0
