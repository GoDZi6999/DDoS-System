"""Notification channels, the delivery outbox, the notifier worker and retention."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import httpx2
import pytest
from sqlalchemy import select, update

from app.core.config import Settings
from app.models import Alert, NetworkEvent, NotificationDelivery
from app.models.enums import AlertStatus, DeliveryStatus
from app.services import senders
from app.services.retention import purge
from app.services.senders import DeliveryError, ensure_public_target, signature, slack_body
from app.workers.notifier import MAX_ATTEMPTS, Notifier
from tests.helpers import audit_actions, count_rows, ingest, run

CHANNELS = "/api/v1/notifications/channels"
DELIVERIES = "/api/v1/notifications/deliveries"
SLACK_URL = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"


def make_channel(client, headers, **overrides):
    body = {
        "name": "SOC mail",
        "kind": "email",
        "min_severity": "HIGH",
        "config": {"recipients": ["soc@example.com"]},
    } | overrides
    response = client.post(CHANNELS, json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def deliveries(client) -> list[NotificationDelivery]:
    async def _query():
        async with client.app.state.sessionmaker() as session:
            return list(
                await session.scalars(
                    select(NotificationDelivery).order_by(NotificationDelivery.id)
                )
            )

    return run(client, _query)


def set_delivery(client, delivery_id: int, **values) -> None:
    async def _update():
        async with client.app.state.sessionmaker() as session:
            await session.execute(
                update(NotificationDelivery)
                .where(NotificationDelivery.id == delivery_id)
                .values(**values)
            )
            await session.commit()

    run(client, _update)


def settings(**overrides) -> Settings:
    return Settings(notify_allow_private_targets=True, **overrides)


def process(client, handler=None, sender=None, **settings_overrides) -> bool:
    async def _process():
        transport = httpx2.MockTransport(handler or (lambda request: httpx2.Response(200)))
        async with httpx2.AsyncClient(transport=transport) as http:
            kwargs = {"sender": sender} if sender else {}
            notifier = Notifier(
                client.app.state.sessionmaker, http, settings(**settings_overrides), **kwargs
            )
            return await notifier.process_one()

    return run(client, _process)


# --- channel API -------------------------------------------------------------


def test_channel_secrets_are_masked_and_changes_audited(client, admin_headers):
    slack = make_channel(
        client, admin_headers, name="Slack", kind="slack", config={"webhook_url": SLACK_URL}
    )
    assert slack["config"] == {"webhook_url": "https://hooks.slack.com/…mnop"}
    assert "abcdefghijklmnop" not in json.dumps(client.get(CHANNELS, headers=admin_headers).json())

    hook = make_channel(
        client,
        admin_headers,
        name="SIEM",
        kind="webhook",
        config={"url": "https://siem.example.com/ingest?token=x", "secret": "s" * 32},
    )
    # The query string (often a token) is hidden.
    assert hook["config"] == {"url": "https://siem.example.com/ingest", "secret_set": True}

    # Omitting the secret keeps it; null removes it.
    path = f"{CHANNELS}/{hook['id']}"
    kept = client.patch(
        path, json={"config": {"url": "https://siem.example.com/v2"}}, headers=admin_headers
    )
    assert kept.json()["config"]["secret_set"] is True
    removed = client.patch(
        path,
        json={"config": {"url": "https://siem.example.com/v2", "secret": None}},
        headers=admin_headers,
    )
    assert removed.json()["config"]["secret_set"] is False

    entries = audit_actions(client, "notification.channel_created")
    assert len(entries) == 2
    assert "abcdefghijklmnop" not in json.dumps([e.after for e in entries])
    assert len(audit_actions(client, "notification.channel_updated")) == 2


@pytest.mark.parametrize(
    ("kind", "config"),
    [
        ("email", {"recipients": []}),
        ("email", {"recipients": ["not-an-address"]}),
        ("slack", {"webhook_url": "http://hooks.slack.com/services/x"}),
        ("webhook", {"url": "https://example.com", "secret": "short"}),
        ("webhook", {"url": "https://example.com", "extra": 1}),
    ],
)
def test_invalid_channel_settings_are_rejected(client, admin_headers, kind, config):
    response = client.post(
        CHANNELS,
        json={"name": "bad", "kind": kind, "config": config},
        headers=admin_headers,
    )
    assert response.status_code == 422, response.text


def test_channel_names_are_unique(client, admin_headers):
    make_channel(client, admin_headers)
    response = client.post(
        CHANNELS,
        json={"name": "soc MAIL", "kind": "email", "config": {"recipients": ["a@example.com"]}},
        headers=admin_headers,
    )
    assert response.status_code == 409


def test_test_message_is_queued_and_listed(client, admin_headers):
    channel = make_channel(client, admin_headers)
    response = client.post(f"{CHANNELS}/{channel['id']}/test", headers=admin_headers)
    assert response.status_code == 202

    page = client.get(DELIVERIES, headers=admin_headers).json()
    assert page["total"] == 1
    item = page["items"][0]
    assert (item["event"], item["status"], item["channel"]["name"]) == (
        "test",
        "pending",
        "SOC mail",
    )
    assert len(audit_actions(client, "notification.test_sent")) == 1


# --- outbox ------------------------------------------------------------------


def test_alert_creation_queues_one_delivery_per_matching_channel(client, admin_headers):
    make_channel(client, admin_headers, name="high", min_severity="HIGH")
    make_channel(client, admin_headers, name="critical-only", min_severity="CRITICAL")
    make_channel(client, admin_headers, name="off", min_severity="LOW", enabled=False)

    ingest(client, risk_score=70)  # HIGH
    for _ in range(5):
        ingest(client, risk_score=70)  # same alert, same band: nothing new

    queued = deliveries(client)
    assert len(queued) == 1
    assert queued[0].event == "alert.created"
    assert queued[0].payload["alert"]["severity"] == "HIGH"
    assert queued[0].payload["url"].endswith(f"/alerts/{queued[0].alert_id}")


def test_escalation_notifies_once_per_new_severity_band(client, admin_headers):
    make_channel(client, admin_headers, min_severity="MEDIUM")
    ingest(client, risk_score=50)  # MEDIUM: created
    ingest(client, risk_score=70)  # HIGH: escalated
    ingest(client, risk_score=75)  # still HIGH
    ingest(client, risk_score=95)  # CRITICAL: escalated

    events = [(d.event, d.payload["alert"]["severity"]) for d in deliveries(client)]
    assert events == [
        ("alert.created", "MEDIUM"),
        ("alert.escalated", "HIGH"),
        ("alert.escalated", "CRITICAL"),
    ]


def test_alert_crossing_a_channel_threshold_later_is_notified(client, admin_headers):
    make_channel(client, admin_headers, min_severity="CRITICAL")
    ingest(client, risk_score=50)
    assert deliveries(client) == []
    ingest(client, risk_score=90)
    assert [d.event for d in deliveries(client)] == ["alert.escalated"]


def test_channel_rate_limit_suppresses_excess_deliveries(client, admin_headers):
    make_channel(client, admin_headers, max_per_hour=1)
    ingest(client, risk_score=90, dst_ip="203.0.113.1")
    ingest(client, risk_score=90, dst_ip="203.0.113.2")

    statuses = [(d.status, d.last_error) for d in deliveries(client)]
    assert statuses[0] == (DeliveryStatus.PENDING, None)
    assert statuses[1][0] == DeliveryStatus.SUPPRESSED
    assert "rate limit" in statuses[1][1]


# --- worker and senders ------------------------------------------------------


def test_webhook_delivery_is_signed(client, admin_headers):
    secret = "k" * 32
    make_channel(
        client,
        admin_headers,
        name="hook",
        kind="webhook",
        config={"url": "https://receiver.example.com/sentinel", "secret": secret},
    )
    ingest(client, risk_score=90)
    received: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        received.append(request)
        return httpx2.Response(204)

    assert process(client, handler) is True
    assert process(client, handler) is False  # nothing else due

    (request,) = received
    body = request.content
    timestamp = request.headers["x-sentinel-timestamp"]
    assert request.headers["x-sentinel-signature"] == signature(secret, timestamp, body)
    assert request.headers["x-sentinel-event"] == "alert.created"
    document = json.loads(body)
    assert document["alert"]["severity"] == "CRITICAL"
    assert document["delivery_id"] == int(request.headers["x-sentinel-delivery"])

    (delivery,) = deliveries(client)
    assert (delivery.status, delivery.attempts) == (DeliveryStatus.SENT, 1)
    assert delivery.sent_at is not None


def test_transient_failures_are_retried_then_marked_failed(client, admin_headers):
    make_channel(
        client, admin_headers, name="hook", kind="webhook", config={"url": "https://r.example"}
    )
    ingest(client, risk_score=90)

    def failing(request):
        return httpx2.Response(503, text="maintenance")

    assert process(client, failing)
    (delivery,) = deliveries(client)
    assert delivery.status == DeliveryStatus.PENDING
    assert delivery.attempts == 1
    assert delivery.next_attempt_at > datetime.now(UTC)
    assert "HTTP 503" in delivery.last_error
    assert process(client, failing) is False  # backing off

    set_delivery(client, delivery.id, attempts=MAX_ATTEMPTS - 1, next_attempt_at=datetime.now(UTC))
    assert process(client, failing)
    (delivery,) = deliveries(client)
    assert (delivery.status, delivery.attempts) == (DeliveryStatus.FAILED, MAX_ATTEMPTS)


def test_client_errors_fail_without_retry(client, admin_headers):
    make_channel(
        client, admin_headers, name="hook", kind="webhook", config={"url": "https://r.example"}
    )
    ingest(client, risk_score=90)
    process(client, lambda request: httpx2.Response(404))
    (delivery,) = deliveries(client)
    assert (delivery.status, delivery.attempts) == (DeliveryStatus.FAILED, 1)


def test_disabled_channel_suppresses_queued_delivery(client, admin_headers):
    channel = make_channel(client, admin_headers)
    ingest(client, risk_score=90)
    client.patch(f"{CHANNELS}/{channel['id']}", json={"enabled": False}, headers=admin_headers)
    process(client)
    (delivery,) = deliveries(client)
    assert delivery.status == DeliveryStatus.SUPPRESSED


def test_email_without_smtp_fails_with_a_clear_reason(client, admin_headers):
    make_channel(client, admin_headers)
    ingest(client, risk_score=90)
    process(client, smtp_host=None)
    (delivery,) = deliveries(client)
    assert delivery.status == DeliveryStatus.FAILED
    assert "SMTP_HOST" in delivery.last_error


def test_email_is_sent_through_smtp(client, admin_headers, monkeypatch):
    sent: list[EmailMessage] = []
    monkeypatch.setattr(senders, "_smtp_send", lambda _settings, message: sent.append(message))
    make_channel(client, admin_headers, config={"recipients": ["a@example.com", "b@example.com"]})
    ingest(client, risk_score=90)

    process(client, smtp_host="mail.example.com", smtp_from="SentinelAI <soc@example.com>")

    (message,) = sent
    assert message["To"] == "a@example.com, b@example.com"
    assert message["Subject"].startswith("[CRITICAL] new alert: DDoS detected")
    body = message.get_content()
    assert "Recommended action (advisory; SentinelAI does not block traffic)" in body
    assert "/alerts/1" in body
    assert deliveries(client)[0].status == DeliveryStatus.SENT


def test_unexpected_sender_errors_do_not_stop_the_worker(client, admin_headers):
    async def broken(*_args):
        raise RuntimeError("bug")

    make_channel(client, admin_headers)
    ingest(client, risk_score=90)
    assert process(client, sender=broken)
    (delivery,) = deliveries(client)
    assert delivery.status == DeliveryStatus.PENDING
    assert delivery.last_error == "Internal error: RuntimeError"


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/hook",
        "https://localhost/hook",
        "https://10.0.0.5/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/hook",
        "http://93.184.216.34/hook",
    ],
)
def test_private_or_plain_http_targets_are_refused(url):
    with pytest.raises(DeliveryError) as error:
        asyncio.run(ensure_public_target(url, allow_private=False))
    assert error.value.permanent


def test_private_targets_allowed_when_configured():
    asyncio.run(ensure_public_target("http://receiver:8080/hook", allow_private=True))


def test_slack_message_escapes_markup():
    payload = {
        "event": "alert.created",
        "url": "http://localhost:3000/alerts/1",
        "alert": {
            "id": 1,
            "severity": "HIGH",
            "attack_type": "webattack",
            "description": "Web attack <script> & co",
            "source_ip": "198.51.100.7",
            "destination_ip": "203.0.113.10",
            "destination_port": 80,
            "protocol": "tcp",
            "risk_score": 70,
            "confidence": 0.9,
            "detection_count": 1,
            "first_seen_at": "2026-10-04T00:00:00+00:00",
            "recommended_action": "Block <x>",
        },
    }
    body = json.dumps(slack_body(payload))
    assert "<script>" not in body and "&lt;script&gt; &amp; co" in body
    assert "<http://localhost:3000/alerts/1|Open in SentinelAI>" in body


# --- retention ---------------------------------------------------------------


def test_retention_keeps_evidence_and_recent_flows(client, admin_headers):
    now = datetime.now(UTC)
    old = now - timedelta(days=30)
    benign_old = ingest(client, ts=old, label="benign", risk_score=0, dst_ip="203.0.113.50")
    benign_new = ingest(client, ts=now, label="benign", risk_score=0, dst_ip="203.0.113.50")
    open_alert = ingest(client, ts=old, risk_score=90, dst_ip="203.0.113.60")
    closed_long_ago = ingest(client, ts=old, risk_score=90, dst_ip="203.0.113.70")

    channel = make_channel(client, admin_headers, min_severity="LOW")
    client.post(f"{CHANNELS}/{channel['id']}/test", headers=admin_headers)
    client.post(f"{CHANNELS}/{channel['id']}/test", headers=admin_headers)
    old_sent, still_pending = deliveries(client)
    set_delivery(client, still_pending.id, created_at=now - timedelta(days=40))
    set_delivery(client, old_sent.id, status="sent", created_at=now - timedelta(days=40))

    async def _close_and_purge():
        async with client.app.state.sessionmaker() as session:
            await session.execute(
                update(Alert)
                .where(Alert.id == closed_long_ago.alert.id)
                .values(status=AlertStatus.RESOLVED, resolved_at=now - timedelta(days=120))
            )
            await session.commit()
            result = await purge(session, Settings(), now=now)
            remaining = set(await session.scalars(select(NetworkEvent.id)))
            return result, remaining

    result, remaining = run(client, _close_and_purge)
    assert remaining == {benign_new.event_id, open_alert.event_id}
    assert benign_old.event_id not in remaining
    assert closed_long_ago.event_id not in remaining
    assert (result.events, result.deliveries) == (2, 1)
    assert channel["id"]  # channel itself is never purged
    assert count_rows(client, Alert) == 2  # alerts are never purged
    (entry,) = audit_actions(client, "retention.purged")
    assert entry.after["network_events"] == 2
