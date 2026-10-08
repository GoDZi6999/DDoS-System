"""API keys (admin) and the /v2 machine API: detect and flow ingest."""

import csv
import json
from pathlib import Path

import pytest

from app.core import config
from app.models import ApiKey
from app.services import detector
from app.services.api_keys import hash_key
from tests.helpers import audit_actions, run

PROFILES = Path(__file__).resolve().parents[2] / "data" / "samples" / "flow_profiles.csv"
T0 = 1_790_000_000.0


def profile_flows(label: str, count: int) -> list[dict]:
    """Flow records built from held-out CIC-IDS2017 flow statistics."""
    flows = []
    with PROFILES.open() as fh:
        for row in csv.DictReader(fh):
            if row.pop("label") != label:
                continue
            features = {name: float(value) for name, value in row.items()}
            duration = features["flow_duration_s"]
            packets = int(features["fwd_packets"] + features["bwd_packets"])
            flows.append(
                {
                    "src_ip": "198.51.100.7",
                    "dst_ip": "10.0.0.5",
                    "src_port": 40000 + len(flows),
                    "dst_port": 80,
                    "protocol": "tcp",
                    "start": T0,
                    "end": T0 + duration,
                    "duration": duration,
                    "packet_count": max(packets, 1),
                    "byte_count": int(features["fwd_bytes"] + features["bwd_bytes"]),
                    "features": features,
                }
            )
            if len(flows) == count:
                return flows
    raise AssertionError(f"not enough {label} profiles")


def create_key(client, admin_headers, name="customer-app", scopes=("detect", "ingest")) -> dict:
    response = client.post(
        "/api/v1/api-keys", json={"name": name, "scopes": list(scopes)}, headers=admin_headers
    )
    assert response.status_code == 201, response.text
    return response.json()


def key_header(created: dict) -> dict[str, str]:
    return {"X-API-Key": created["key"]}


# --- API keys -------------------------------------------------------------


def test_admin_creates_lists_and_revokes_keys_and_only_the_hash_is_stored(client, admin_headers):
    created = create_key(client, admin_headers)

    assert created["key"].startswith(f"argus_{created['prefix']}_")
    assert created["scopes"] == ["detect", "ingest"]
    listed = client.get("/api/v1/api-keys", headers=admin_headers).json()
    assert listed["total"] == 1
    assert "key" not in listed["items"][0]
    assert "key_hash" not in listed["items"][0]

    async def stored_hash():
        async with client.app.state.sessionmaker() as session:
            return (await session.get(ApiKey, created["id"])).key_hash

    assert run(client, stored_hash) == hash_key(created["key"])

    revoked = client.post(f"/api/v1/api-keys/{created['id']}/revoke", headers=admin_headers)
    assert revoked.status_code == 200 and revoked.json()["revoked_at"] is not None
    assert {a.action for a in audit_actions(client)} >= {"api_key.created", "api_key.revoked"}


def test_duplicate_key_names_conflict(client, admin_headers):
    create_key(client, admin_headers)
    response = client.post(
        "/api/v1/api-keys",
        json={"name": "customer-app", "scopes": ["detect"]},
        headers=admin_headers,
    )
    assert response.status_code == 409


def test_unknown_scope_is_rejected(client, admin_headers):
    response = client.post(
        "/api/v1/api-keys", json={"name": "x", "scopes": ["admin"]}, headers=admin_headers
    )
    assert response.status_code == 422


# --- authentication --------------------------------------------------------


def test_v2_requires_a_valid_active_key_with_the_right_scope(client, admin_headers):
    flows = profile_flows("benign", 1)
    assert client.post("/v2/flows", json={"flows": flows}).status_code == 401
    bad = {"X-API-Key": "argus_00000000_not-a-real-key"}
    assert client.post("/v2/flows", json={"flows": flows}, headers=bad).status_code == 401

    detect_only = create_key(client, admin_headers, "detect-only", ["detect"])
    response = client.post("/v2/flows", json={"flows": flows}, headers=key_header(detect_only))
    assert response.status_code == 403

    ingest = create_key(client, admin_headers, "ingest", ["ingest"])
    client.post(f"/api/v1/api-keys/{ingest['id']}/revoke", headers=admin_headers)
    response = client.post("/v2/flows", json={"flows": flows}, headers=key_header(ingest))
    assert response.status_code == 401


def test_a_user_session_token_is_not_an_api_key(client, admin_headers):
    response = client.post(
        "/v2/flows", json={"flows": profile_flows("benign", 1)}, headers=admin_headers
    )
    assert response.status_code == 401


def test_rate_limit_per_key(client, admin_headers, monkeypatch):
    monkeypatch.setenv("API_RATE_PER_MINUTE", "2")
    config.get_settings.cache_clear()
    created = create_key(client, admin_headers)
    body = {"flows": profile_flows("benign", 1)}

    codes = [
        client.post("/v2/flows", json=body, headers=key_header(created)).status_code
        for _ in range(3)
    ]

    assert codes == [202, 202, 429]
    config.get_settings.cache_clear()


def test_batch_size_and_flow_validation(client, admin_headers, monkeypatch):
    monkeypatch.setenv("API_MAX_FLOWS", "2")
    config.get_settings.cache_clear()
    headers = key_header(create_key(client, admin_headers))

    too_many = client.post("/v2/flows", json={"flows": profile_flows("benign", 3)}, headers=headers)
    assert too_many.status_code == 413

    broken = profile_flows("benign", 1)
    broken[0]["end"] = broken[0]["start"] - 1
    assert client.post("/v2/flows", json={"flows": broken}, headers=headers).status_code == 422
    broken = profile_flows("benign", 1)
    broken[0]["features"]["flow_iat_mean"] = float("inf")
    raw = json.dumps({"flows": broken}).replace("Infinity", "1e400")
    response = client.post(
        "/v2/flows", content=raw, headers=headers | {"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    config.get_settings.cache_clear()


# --- POST /v2/flows ----------------------------------------------------------


def test_ingest_queues_flows_on_the_sensor_stream(client, admin_headers, redis_client):
    created = create_key(client, admin_headers)
    flows = profile_flows("ddos", 3)

    response = client.post("/v2/flows", json={"flows": flows}, headers=key_header(created))

    assert response.status_code == 202
    sensor = f"api-{created['prefix']}"
    assert response.json() == {"accepted": 3, "sensor": sensor}
    entries = redis_client.xrange("sentinel:flows")
    assert len(entries) == 3
    fields = entries[0][1]
    assert fields[b"v"] == b"1" and fields[b"sensor"] == sensor.encode()
    record = json.loads(fields[b"data"])
    assert record["dst_ip"] == "10.0.0.5" and record["features"] == flows[0]["features"]
    status = redis_client.hgetall(f"sentinel:sensors:{sensor}")
    assert status[b"flows_sent"] == b"3" and status[b"state"] == b"running"

    listed = client.get("/api/v1/sensors", headers=admin_headers).json()
    assert [s["name"] for s in listed["items"]] == [sensor]


# --- POST /v2/detect ---------------------------------------------------------


@pytest.fixture
def detect_headers(client, admin_headers):
    pytest.importorskip("sentinel_ml")
    return key_header(create_key(client, admin_headers, "detector", ["detect"]))


def test_detect_returns_a_verdict_per_flow_with_reasons_for_attacks(
    client, detect_headers, redis_client
):
    flows = profile_flows("ddos", 5) + profile_flows("benign", 5)

    response = client.post("/v2/detect", json={"flows": flows}, headers=detect_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model_version"].startswith("sentinel-flow-")
    results = body["results"]
    assert [r["index"] for r in results] == list(range(10))
    assert sum(r["label"] == "ddos" for r in results[:5]) >= 4
    assert sum(r["label"] == "benign" for r in results[5:]) >= 4
    assert body["attacks"] == sum(r["is_attack"] for r in results)
    attack = next(r for r in results if r["is_attack"])
    assert attack["explanation"] and attack["recommended_action"]
    assert 0 < attack["confidence"] <= 1
    benign = next(r for r in results if not r["is_attack"])
    assert benign["explanation"] == [] and benign["recommended_action"] is None
    # Stateless: nothing reaches the alert pipeline.
    assert redis_client.exists("sentinel:flows") == 0


def test_detect_explains_at_most_the_configured_number_of_attacks(
    client, detect_headers, monkeypatch
):
    monkeypatch.setenv("API_MAX_EXPLAINED", "2")
    config.get_settings.cache_clear()

    body = client.post(
        "/v2/detect", json={"flows": profile_flows("ddos", 6)}, headers=detect_headers
    ).json()

    assert body["attacks"] >= 3
    assert sum(bool(r["explanation"]) for r in body["results"]) == 2
    config.get_settings.cache_clear()


def test_detect_rejects_flows_missing_model_features(client, detect_headers):
    flows = profile_flows("benign", 1)
    del flows[0]["features"]["init_win_bytes_fwd"]

    response = client.post("/v2/detect", json={"flows": flows}, headers=detect_headers)

    assert response.status_code == 422
    assert "init_win_bytes_fwd" in response.json()["detail"]


def test_detect_is_unavailable_without_a_model(client, admin_headers, monkeypatch, tmp_path):
    monkeypatch.setenv("MODEL_BUNDLE", str(tmp_path / "missing"))
    config.get_settings.cache_clear()
    headers = key_header(create_key(client, admin_headers, "detector", ["detect"]))

    response = client.post(
        "/v2/detect", json={"flows": profile_flows("benign", 1)}, headers=headers
    )

    assert response.status_code == 503
    config.get_settings.cache_clear()
    detector._load.cache_clear()
