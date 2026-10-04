"""Delivery of one notification over email (SMTP), Slack or a signed webhook.

Senders raise DeliveryError; `permanent` errors (a 4xx answer, a refused
recipient, a target that resolves to a private address) are not retried.
"""

import asyncio
import hashlib
import hmac
import json
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import httpx2

from app.core.config import Settings
from app.models import NotificationChannel, NotificationDelivery
from app.models.enums import ChannelKind
from app.services.notifications import title

USER_AGENT = "SentinelAI-Notifier/1.0"
HTTP_TIMEOUT_S = 10.0
SMTP_TIMEOUT_S = 15.0


class DeliveryError(Exception):
    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


# --- message text ------------------------------------------------------------


def text_body(payload: dict[str, Any]) -> str:
    alert = payload.get("alert")
    if not alert:
        return (
            f"This is a test notification for the SentinelAI channel '{payload.get('channel')}'.\n"
            f"If you can read it, the channel works.\n\nDashboard: {payload.get('url')}\n"
        )
    port = alert["destination_port"]
    target = alert["destination_ip"] + (f":{port}" if port is not None else "")
    return "\n".join(
        [
            title(payload),
            "",
            f"Target:      {target} ({alert['protocol']})",
            f"Source:      {alert['source_ip']}",
            f"Risk score:  {alert['risk_score']}/100 ({alert['severity']}), "
            f"model confidence {alert['confidence'] * 100:.1f}%",
            f"Detections:  {alert['detection_count']} since {alert['first_seen_at']}",
            "",
            "Recommended action (advisory; SentinelAI does not block traffic):",
            alert["recommended_action"],
            "",
            f"Open in SentinelAI: {payload['url']}",
            "",
        ]
    )


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_body(payload: dict[str, Any]) -> dict[str, Any]:
    heading = _slack_escape(title(payload))
    alert = payload.get("alert")
    if not alert:
        return {"text": heading}
    port = alert["destination_port"]
    target = alert["destination_ip"] + (f":{port}" if port is not None else "")
    fields = [
        ("Target", f"{target} ({alert['protocol']})"),
        ("Source", alert["source_ip"]),
        ("Risk", f"{alert['risk_score']}/100 ({alert['severity']})"),
        ("Confidence", f"{alert['confidence'] * 100:.1f}%"),
    ]
    return {
        "text": heading,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{heading}*"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{name}*\n{_slack_escape(value)}"}
                    for name, value in fields
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Recommended action* (advisory)\n"
                    + _slack_escape(alert["recommended_action"]),
                },
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"<{payload['url']}|Open in SentinelAI>"}],
            },
        ],
    }


def webhook_body(delivery: NotificationDelivery) -> bytes:
    document = {"delivery_id": delivery.id, **delivery.payload}
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def signature(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over "<timestamp>.<body>"; receivers should also reject old timestamps."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


# --- transport ---------------------------------------------------------------


async def ensure_public_target(url: str, allow_private: bool) -> None:
    """Refuse targets that resolve to loopback, private, link-local or other
    non-public addresses, so a webhook cannot be aimed at internal services.
    (The HTTP client resolves the name again; DNS rebinding between the two
    lookups is a documented residual risk.)"""
    parts = urlsplit(url)
    if not parts.hostname:
        raise DeliveryError("The URL has no host", permanent=True)
    if allow_private:
        return
    if parts.scheme != "https":
        raise DeliveryError("Only https targets are allowed", permanent=True)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            parts.hostname, parts.port or 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise DeliveryError(f"Cannot resolve {parts.hostname}: {exc.strerror}") from exc
    for info in infos:
        address = ip_address(info[4][0])
        if not address.is_global:
            raise DeliveryError(
                f"{parts.hostname} resolves to a non-public address ({address})", permanent=True
            )


async def post(client: httpx2.AsyncClient, url: str, body: bytes, headers: dict[str, str]) -> None:
    try:
        response = await client.post(
            url,
            content=body,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers},
            timeout=HTTP_TIMEOUT_S,
            follow_redirects=False,
        )
    except httpx2.HTTPError as exc:
        raise DeliveryError(f"{type(exc).__name__}: {exc}"[:300]) from exc
    if response.status_code >= 300:
        code = response.status_code
        permanent = 300 <= code < 500 and code not in (408, 425, 429)
        raise DeliveryError(f"HTTP {code}: {response.text[:200]}", permanent=permanent)


def _smtp_send(settings: Settings, message: EmailMessage) -> None:
    assert settings.smtp_host is not None  # noqa: S101 (checked by the caller)
    context = ssl.create_default_context()
    if settings.smtp_security == "tls":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_S, context=context
        )
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_S)
    with server:
        if settings.smtp_security == "starttls":
            server.starttls(context=context)
        if settings.smtp_username:
            password = settings.smtp_password.get_secret_value() if settings.smtp_password else ""
            server.login(settings.smtp_username, password)
        server.send_message(message)


async def send_email(settings: Settings, recipients: list[str], payload: dict[str, Any]) -> None:
    if not settings.smtp_host:
        raise DeliveryError("SMTP is not configured (set SMTP_HOST)", permanent=True)
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(recipients)
    message["Subject"] = " ".join(title(payload).split())[:200]
    message.set_content(text_body(payload))
    try:
        await asyncio.to_thread(_smtp_send, settings, message)
    except smtplib.SMTPRecipientsRefused as exc:
        raise DeliveryError("The SMTP server refused every recipient", permanent=True) from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"SMTP error: {type(exc).__name__}: {exc}"[:300]) from exc


async def send_delivery(
    channel: NotificationChannel,
    delivery: NotificationDelivery,
    client: httpx2.AsyncClient,
    settings: Settings,
) -> None:
    config = channel.config
    allow_private = settings.notify_allow_private_targets
    if channel.kind == ChannelKind.EMAIL:
        await send_email(settings, config["recipients"], delivery.payload)
    elif channel.kind == ChannelKind.SLACK:
        url = config["webhook_url"]
        await ensure_public_target(url, allow_private)
        await post(client, url, json.dumps(slack_body(delivery.payload)).encode(), {})
    else:
        url = config["url"]
        await ensure_public_target(url, allow_private)
        body = webhook_body(delivery)
        timestamp = str(int(time.time()))
        headers = {
            "X-Sentinel-Event": delivery.payload["event"],
            "X-Sentinel-Delivery": str(delivery.id),
            "X-Sentinel-Timestamp": timestamp,
        }
        if config.get("secret"):
            headers["X-Sentinel-Signature"] = signature(config["secret"], timestamp, body)
        await post(client, url, body, headers)
