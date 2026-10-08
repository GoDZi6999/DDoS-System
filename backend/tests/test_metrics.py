from datetime import UTC, datetime

from tests.helpers import ingest


def _value(text: str, prefix: str) -> float:
    line = next(line for line in text.splitlines() if line.startswith(prefix))
    return float(line.rsplit(" ", 1)[1])


def test_metrics_expose_pipeline_state_and_request_timings(client, viewer_headers):
    alert = ingest(client, risk_score=90).alert
    ingest(client, label="benign", risk_score=0, ts=datetime.now(UTC))
    client.get(f"/api/v1/alerts/{alert.id}", headers=viewer_headers)

    response = client.get("/metrics")

    assert response.status_code == 200
    text = response.text
    assert _value(text, 'sentinel_open_alerts{severity="CRITICAL"}') == 1
    assert _value(text, 'sentinel_open_alerts{severity="LOW"}') == 0
    assert _value(text, 'sentinel_flows_last_5m{class="attack"}') == 1
    assert _value(text, 'sentinel_flows_last_5m{class="benign"}') == 1
    assert 'sentinel_detection_stream{state="lag"}' in text
    # Routes are labelled by template, never by raw path (bounded cardinality).
    assert 'route="/api/v1/alerts/{alert_id}"' in text
    assert f'route="/api/v1/alerts/{alert.id}"' not in text


def test_metrics_are_not_part_of_the_documented_api(client):
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]
