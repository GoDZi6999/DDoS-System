"""Packet capture upload and analysis, and packet evidence for alerts."""

from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

from app.core import config
from app.models import Alert, Capture
from app.models.enums import CaptureStatus
from app.services import captures as capture_service
from app.workers.alert_engine import DETECTIONS_STREAM, AlertEngine
from tests.helpers import audit_actions, ingest, run

pytest.importorskip("scapy")

SCANNER = "203.0.113.9"
TARGET = "192.168.1.10"
SCANNED_PORTS = range(1, 41)
T0 = 1_700_000_000.0


def capture_packets() -> list:
    """A short web session plus a SYN scan of 40 ports (each answered by RST)."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    packets = []

    def add(ts: float, pkt) -> None:
        pkt.time = ts
        packets.append(pkt)

    web = ("192.168.1.20", 51000, "93.184.216.34", 443)
    for i, (src, sport, dst, dport, flags) in enumerate(
        [
            (*web, "S"),
            (web[2], web[3], web[0], web[1], "SA"),
            (*web, "A"),
            (*web, "PA"),
            (web[2], web[3], web[0], web[1], "PA"),
            (*web, "FA"),
            (web[2], web[3], web[0], web[1], "FA"),
            (*web, "A"),
        ]
    ):
        add(
            T0 + i * 0.05,
            Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags),
        )
    for i, port in enumerate(SCANNED_PORTS):
        ts = T0 + 1 + i * 0.05
        add(ts, Ether() / IP(src=SCANNER, dst=TARGET) / TCP(sport=60000, dport=port, flags="S"))
        add(
            ts + 0.01,
            Ether() / IP(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=60000, flags="RA"),
        )
    return packets


def pcap_bytes(tmp_path, fmt: str = "pcap") -> bytes:
    from scapy.utils import wrpcap, wrpcapng

    path = tmp_path / f"sample.{fmt}"
    (wrpcapng if fmt == "pcapng" else wrpcap)(str(path), capture_packets())
    return path.read_bytes()


@pytest.fixture
def capture_dir(tmp_path, monkeypatch):
    folder = tmp_path / "captures"
    monkeypatch.setenv("CAPTURE_DIR", str(folder))
    config.get_settings.cache_clear()
    yield folder
    config.get_settings.cache_clear()


def upload(client, headers, data: bytes, filename="scan.pcap", raise_alerts=True):
    return client.post(
        "/api/v1/captures",
        params={"filename": filename, "raise_alerts": str(raise_alerts).lower()},
        content=data,
        headers=headers | {"Content-Type": "application/octet-stream"},
    )


def process_next(client) -> bool:
    from app.workers.capture_analyzer import CaptureWorker

    async def go() -> bool:
        worker = CaptureWorker(client.app.state.sessionmaker, config.get_settings())
        return await worker.process_one()

    return run(client, go)


def deliver_detections(client, redis_client) -> int:
    """Run what the alert engine would do with the published detections."""
    entries = [
        (entry_id.decode(), fields) for entry_id, fields in redis_client.xrange(DETECTIONS_STREAM)
    ]

    async def go() -> None:
        engine = AlertEngine(client.app.state.sessionmaker, client.app.state.redis, "test")
        await engine.ensure_group()
        assert await engine.handle_batch(entries)

    run(client, go)
    return len(entries)


def get_capture(client, capture_id: int) -> Capture:
    async def go() -> Capture:
        async with client.app.state.sessionmaker() as session:
            return await session.get(Capture, capture_id)

    return run(client, go)


# --- upload ---------------------------------------------------------------------


def test_upload_stores_the_file_and_queues_it(client, analyst_headers, capture_dir, tmp_path):
    data = pcap_bytes(tmp_path)

    response = upload(client, analyst_headers, data, filename="../../Monday scan?.pcap")

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued" and body["file_format"] == "pcap"
    assert body["filename"] == "Monday scan_.pcap"
    assert body["size_bytes"] == len(data) and body["report"] is None
    stored = list(capture_dir.iterdir())
    assert len(stored) == 1 and stored[0].read_bytes() == data
    assert [a.action for a in audit_actions(client, "capture.uploaded")] == ["capture.uploaded"]
    listed = client.get("/api/v1/captures", headers=analyst_headers).json()
    assert [c["id"] for c in listed["items"]] == [body["id"]]


def test_upload_rejects_files_that_are_not_captures(client, analyst_headers, capture_dir):
    response = upload(client, analyst_headers, b"GIF89a not a capture")

    assert response.status_code == 422
    assert "pcap" in response.json()["detail"]
    assert list(capture_dir.iterdir()) == []


def test_upload_size_limit(client, analyst_headers, capture_dir, monkeypatch, tmp_path):
    monkeypatch.setenv("CAPTURE_MAX_MB", "1")
    config.get_settings.cache_clear()

    data = pcap_bytes(tmp_path)
    response = upload(client, analyst_headers, data + b"\0" * (1024 * 1024))

    assert response.status_code == 413
    assert list(capture_dir.iterdir()) == []


def test_viewers_cannot_upload(client, viewer_headers, capture_dir, tmp_path):
    assert upload(client, viewer_headers, pcap_bytes(tmp_path)).status_code == 403


# --- analysis -----------------------------------------------------------------------


@pytest.fixture
def model():
    pytest.importorskip("sentinel_ml")
    pytest.importorskip("sentinel_engine")


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_analysis_reports_the_scan_and_raises_an_alert_with_packet_evidence(
    client, analyst_headers, viewer_headers, redis_client, capture_dir, model, tmp_path, fmt
):
    capture_id = upload(client, analyst_headers, pcap_bytes(tmp_path, fmt), f"scan.{fmt}").json()[
        "id"
    ]

    assert process_next(client) is True
    assert process_next(client) is False  # queue empty

    capture = client.get(f"/api/v1/captures/{capture_id}", headers=viewer_headers).json()
    assert capture["status"] == "done", capture["error"]
    report = capture["report"]
    assert report["packets"] == 8 + 2 * len(SCANNED_PORTS)
    assert report["attack_types"].get("portscan", 0) >= 1
    assert {"ip": SCANNER, "detections": report["top_sources"][0]["detections"]} in report[
        "top_sources"
    ]
    assert report["first_packet_at"] == datetime.fromtimestamp(T0, UTC).isoformat()
    # Shifted to end now, so the dashboard's time windows include it.
    assert get_capture(client, capture_id).time_offset > 0

    assert deliver_detections(client, redis_client) == report["flows"]
    alerts = client.get(
        "/api/v1/alerts", params={"attack_type": "portscan"}, headers=viewer_headers
    )
    scan = next(a for a in alerts.json()["items"] if a["attack_type"] == "portscan")
    detail = client.get(f"/api/v1/alerts/{scan['id']}", headers=viewer_headers).json()
    assert detail["evidence_capture_id"] == capture_id
    assert detail["wireshark_filter"] == (
        f"ip.src == {SCANNER} && ip.dst == {TARGET} && tcp.flags.syn == 1"
    )

    assert (
        client.get(f"/api/v1/alerts/{scan['id']}/evidence.pcap", headers=viewer_headers).status_code
        == 403
    )
    response = client.get(f"/api/v1/alerts/{scan['id']}/evidence.pcap", headers=analyst_headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert "argusai-alert-" in response.headers["content-disposition"]

    from scapy.layers.inet import IP
    from scapy.utils import rdpcap

    path = tmp_path / "evidence.pcap"
    path.write_bytes(response.content)
    packets = rdpcap(str(path))
    assert len(packets) == int(response.headers["x-evidence-packets"]) > 0
    # Only the scan's packets, with the capture's original timestamps.
    assert all({p[IP].src, p[IP].dst} == {SCANNER, TARGET} for p in packets)
    assert all(T0 <= float(p.time) <= T0 + 4 for p in packets)
    assert audit_actions(client, "alert.evidence_downloaded")


def test_analysis_without_alerts_only_reports(
    client, analyst_headers, redis_client, capture_dir, model, tmp_path
):
    capture_id = upload(client, analyst_headers, pcap_bytes(tmp_path), raise_alerts=False).json()[
        "id"
    ]

    process_next(client)

    capture = client.get(f"/api/v1/captures/{capture_id}", headers=analyst_headers).json()
    assert capture["status"] == "done" and capture["report"]["flows"] > 0
    assert redis_client.exists(DETECTIONS_STREAM) == 0


def test_a_damaged_capture_fails_with_a_reason(
    client, analyst_headers, capture_dir, model, tmp_path
):
    data = pcap_bytes(tmp_path)
    capture_id = upload(client, analyst_headers, data[:24] + b"\xff" * 64).json()["id"]

    process_next(client)

    capture = client.get(f"/api/v1/captures/{capture_id}", headers=analyst_headers).json()
    assert capture["status"] == "failed"
    assert capture["error"]


def test_interrupted_analyses_are_failed_on_restart(client, analyst_headers, capture_dir, tmp_path):
    capture_id = upload(client, analyst_headers, pcap_bytes(tmp_path)).json()["id"]

    async def interrupt_and_recover() -> int:
        async with client.app.state.sessionmaker() as session:
            await capture_service.claim_next(session)
        async with client.app.state.sessionmaker() as session:
            return await capture_service.fail_interrupted(session)

    assert run(client, interrupt_and_recover) == 1
    capture = get_capture(client, capture_id)
    assert capture.status == CaptureStatus.FAILED and "interrupted" in capture.error


# --- delete -------------------------------------------------------------------------------


def test_admin_deletes_a_capture_and_its_file(
    client, admin_headers, analyst_headers, capture_dir, tmp_path
):
    capture_id = upload(client, analyst_headers, pcap_bytes(tmp_path)).json()["id"]

    assert (
        client.delete(f"/api/v1/captures/{capture_id}", headers=analyst_headers).status_code == 403
    )
    assert client.delete(f"/api/v1/captures/{capture_id}", headers=admin_headers).status_code == 204

    assert list(capture_dir.iterdir()) == []
    assert client.get(f"/api/v1/captures/{capture_id}", headers=admin_headers).status_code == 404
    assert audit_actions(client, "capture.deleted")


def test_a_capture_being_analysed_cannot_be_deleted(
    client, admin_headers, analyst_headers, capture_dir, tmp_path
):
    capture_id = upload(client, analyst_headers, pcap_bytes(tmp_path)).json()["id"]

    async def claim() -> None:
        async with client.app.state.sessionmaker() as session:
            await capture_service.claim_next(session)

    run(client, claim)
    assert client.delete(f"/api/v1/captures/{capture_id}", headers=admin_headers).status_code == 409


# --- evidence for other alerts ------------------------------------------------------------


def test_alerts_from_live_traffic_have_a_filter_but_no_packets(
    client, analyst_headers, capture_dir
):
    alert_id = ingest(client).alert.id

    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=analyst_headers).json()
    assert detail["evidence_capture_id"] is None
    assert detail["wireshark_filter"] == "ip.dst == 203.0.113.10 && tcp.dstport == 80"
    response = client.get(f"/api/v1/alerts/{alert_id}/evidence.pcap", headers=analyst_headers)
    assert response.status_code == 422
    assert "Wireshark filter" in response.json()["detail"]


@pytest.mark.parametrize(
    ("attack_type", "src", "dst", "port", "protocol", "expected"),
    [
        ("ddos", "198.51.100.7", "10.0.0.5", 80, "tcp", "ip.dst == 10.0.0.5 && tcp.dstport == 80"),
        ("dos", "198.51.100.7", "10.0.0.5", None, "icmp", "ip.dst == 10.0.0.5"),
        (
            "bruteforce",
            "198.51.100.7",
            "10.0.0.5",
            22,
            "tcp",
            "ip.addr == 198.51.100.7 && ip.addr == 10.0.0.5 && tcp.port == 22",
        ),
        (
            "botnet",
            "2001:db8::7",
            "10.0.0.5",
            53,
            "udp",
            "ipv6.addr == 2001:db8::7 && ip.addr == 10.0.0.5 && udp.port == 53",
        ),
    ],
)
def test_wireshark_filter(attack_type, src, dst, port, protocol, expected):
    alert = Alert(
        attack_type=attack_type,
        source_ip=ip_address(src),
        destination_ip=ip_address(dst),
        destination_port=port,
        protocol=protocol,
    )
    assert capture_service.wireshark_filter(alert) == expected


def test_the_demo_capture_shows_a_flood_and_a_scan(model, tmp_path):
    """The smoke test and docs rely on `python -m app.cli demo-capture`."""
    from sentinel_ml.inference import Predictor

    from app.services.capture_analysis import analyze
    from app.services.demo_capture import build
    from app.services.detector import DEFAULT_BUNDLE

    path = tmp_path / "demo.pcap"
    packets = build(path)

    report = analyze(path, 1, Predictor.from_bundle(DEFAULT_BUNDLE)).report

    assert report["packets"] == packets
    assert report["attack_types"]["ddos"] >= 500 + 1500
    assert report["attack_types"]["portscan"] >= 1
    # The HTTP flood is the model's; the SYN flood looks benign to it.
    assert report["detected_by"]["model"] >= 500
    assert report["detected_by"]["rule:flood-v1"] >= 1500
