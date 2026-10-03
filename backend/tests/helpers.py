"""Helpers that run async setup code on the TestClient's event loop (the app's
engine and Redis client are bound to that loop)."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.security import create_access_token, hash_password
from app.models import AuditLog, User
from app.models.enums import Role
from app.schemas.config import DetectionConfig
from app.schemas.detection import Detection
from app.services.alerts import IngestResult, ingest_detection

PASSWORD = "correct-horse-battery-staple"


def run(client: TestClient, fn: Callable[..., Awaitable[Any]], *args: Any) -> Any:
    return client.portal.call(fn, *args)


def create_user(
    client: TestClient,
    username: str,
    role: Role = Role.VIEWER,
    password: str = PASSWORD,
    is_active: bool = True,
) -> int:
    async def _create() -> int:
        async with client.app.state.sessionmaker() as session:
            user = User(
                username=username,
                role=role,
                password_hash=hash_password(password),
                is_active=is_active,
            )
            session.add(user)
            await session.commit()
            return user.id

    return run(client, _create)


def bearer(user_id: int, token_version: int = 0) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(user_id, token_version).token}"}


def login(client: TestClient, username: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", data={"username": username, "password": password})


def audit_actions(client: TestClient, action: str | None = None) -> list[AuditLog]:
    async def _query() -> list[AuditLog]:
        async with client.app.state.sessionmaker() as session:
            stmt = select(AuditLog).order_by(AuditLog.id)
            if action is not None:
                stmt = stmt.where(AuditLog.action == action)
            return list(await session.scalars(stmt))

    return run(client, _query)


async def count_rows_async(client: TestClient, model: type) -> int:
    async with client.app.state.sessionmaker() as session:
        return await session.scalar(select(func.count()).select_from(model))


def count_rows(client: TestClient, model: type) -> int:
    return run(client, count_rows_async, client, model)


def detection(**overrides: Any) -> Detection:
    fields: dict[str, Any] = {
        "ts": datetime.now(UTC),
        "src_ip": "198.51.100.7",
        "dst_ip": "203.0.113.10",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": "tcp",
        "packet_count": 5000,
        "byte_count": 300000,
        "duration": 1.0,
        "packets_per_sec": 5000.0,
        "bytes_per_sec": 300000.0,
        "features": {"syn_ratio": 0.9},
        "source": "sim",
        "label": "ddos",
        "confidence": 0.97,
        "class_probs": {"ddos": 0.97, "benign": 0.03},
        "explanation": [
            {"feature": "packets_per_sec", "value": 5000.0, "contribution": 0.4, "weight": 60.0},
            {"feature": "syn_ratio", "value": 0.9, "contribution": 0.25, "weight": 40.0},
        ],
        "risk_score": 85,
        "risk_components": {"ml_confidence": 97, "traffic_anomaly": 90},
        "model_version": "test-model-1",
    }
    return Detection.model_validate(fields | overrides)


def ingest(
    client: TestClient,
    config: DetectionConfig | None = None,
    stream_id: str | None = None,
    **overrides: Any,
) -> IngestResult:
    async def _ingest() -> IngestResult:
        async with client.app.state.sessionmaker() as session:
            result = await ingest_detection(
                session, detection(**overrides), config or DetectionConfig(), stream_id=stream_id
            )
            await session.commit()
            return result

    return run(client, _ingest)
