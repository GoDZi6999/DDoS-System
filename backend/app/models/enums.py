from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    def includes(self, required: "Role") -> bool:
        """Roles are hierarchical: admin > analyst > viewer."""
        return _ROLE_RANK[self] >= _ROLE_RANK[required]


_ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


class AlertStatus(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


OPEN_ALERT_STATUSES = frozenset({AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.CONTAINED})


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def severity_for(risk_score: int) -> Severity:
    """Risk bands from the architecture: 0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CRITICAL."""
    if risk_score <= 30:
        return Severity.LOW
    if risk_score <= 60:
        return Severity.MEDIUM
    if risk_score <= 80:
        return Severity.HIGH
    return Severity.CRITICAL


class EventSource(StrEnum):
    LIVE = "live"
    PCAP = "pcap"
    SIM = "sim"


class ChannelKind(StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"


class NotificationEvent(StrEnum):
    ALERT_CREATED = "alert.created"
    ALERT_ESCALATED = "alert.escalated"
    TEST = "test"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class ApiScope(StrEnum):
    """What a /v2 API key may do."""

    DETECT = "detect"  # POST /v2/detect: classify flows and get the verdict back
    INGEST = "ingest"  # POST /v2/flows: hand flows to the real-time engine (alerts)
