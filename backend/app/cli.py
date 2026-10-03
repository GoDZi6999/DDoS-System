"""Operational commands.

python -m app.cli bootstrap              create the first admin user (idempotent)
python -m app.cli reset-password USER    set a new generated password (account recovery)
python -m app.cli demo-detections        publish synthetic detections (pipeline testing)
"""

import argparse
import asyncio
import random
import secrets
import sys
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.session import create_engine, create_sessionmaker
from app.models import User
from app.models.enums import EventSource, Role
from app.schemas.detection import Detection, ExplanationItem
from app.schemas.user import UserCreate
from app.services.audit import SYSTEM_ACTOR, record_audit
from app.services.auth import end_all_sessions
from app.workers.alert_engine import DETECTIONS_STREAM

DEMO_STREAM_MAXLEN = 100_000


async def bootstrap() -> int:
    """Create the initial admin if the database has no users yet."""
    settings = get_settings()
    configured = settings.initial_admin_password
    password = configured.get_secret_value() if configured else secrets.token_urlsafe(18)
    try:
        # Reuse the API's validation rules for username and password length.
        data = UserCreate(
            username=settings.initial_admin_username, password=password, role=Role.ADMIN
        )
    except ValueError as exc:
        print(f"Invalid INITIAL_ADMIN_USERNAME or INITIAL_ADMIN_PASSWORD: {exc}", file=sys.stderr)
        return 2

    engine = create_engine(settings.database_url)
    try:
        async with create_sessionmaker(engine)() as session:
            if await session.scalar(select(func.count()).select_from(User)):
                print("Users already exist; bootstrap skipped.")
                return 0
            user = User(
                username=data.username, password_hash=hash_password(password), role=Role.ADMIN
            )
            session.add(user)
            await session.flush()
            record_audit(
                session,
                SYSTEM_ACTOR,
                "user.created",
                entity_type="user",
                entity_id=user.id,
                after={"username": user.username, "role": "admin", "source": "bootstrap"},
            )
            await session.commit()
    finally:
        await engine.dispose()

    print(f"Created admin user '{data.username}'.")
    if configured is None:
        print(f"Generated password (shown once, change it after logging in): {password}")
    return 0


async def reset_password(username: str) -> int:
    """Recovery path for a lost password (e.g. the bootstrap admin's): generates a
    new password, ends the user's sessions and records the reset in the audit log."""
    username = username.strip().lower()
    password = secrets.token_urlsafe(18)
    engine = create_engine(get_settings().database_url)
    try:
        async with create_sessionmaker(engine)() as session:
            user = await session.scalar(select(User).where(User.username == username))
            if user is None:
                print(f"No user named '{username}'.", file=sys.stderr)
                return 1
            user.password_hash = hash_password(password)
            await end_all_sessions(session, user)
            record_audit(
                session,
                SYSTEM_ACTOR,
                "user.updated",
                entity_type="user",
                entity_id=user.id,
                after={"password_reset": True, "source": "cli"},
            )
            await session.commit()
    finally:
        await engine.dispose()
    print(f"New password for '{username}' (shown once, change it after logging in): {password}")
    return 0


def _demo_detection(index: int, count: int, target: str, label: str) -> Detection:
    """A flood ramping up over `count` flows, from documentation-range sources."""
    rng = random.Random(index)  # noqa: S311 (synthetic data, not security-sensitive)
    ramp = (index + 1) / count
    pps = 2_000 + 48_000 * ramp + rng.uniform(-500, 500)
    risk = min(100, int(45 + 50 * ramp))
    return Detection(
        ts=datetime.now(UTC) - timedelta(seconds=count - index),
        src_ip=f"198.51.100.{rng.randint(1, 254)}",
        dst_ip=target,
        src_port=rng.randint(1024, 65535),
        dst_port=80,
        protocol="tcp",
        packet_count=int(pps * 2),
        byte_count=int(pps * 2 * 60),
        duration=2.0,
        packets_per_sec=pps,
        bytes_per_sec=pps * 60,
        features={"syn_ratio": 0.6 + 0.35 * ramp, "unique_sources": 10 + 400 * ramp},
        source=EventSource.SIM,
        label=label,
        confidence=round(0.80 + 0.19 * ramp, 3),
        class_probs={label: round(0.80 + 0.19 * ramp, 3)},
        explanation=[
            ExplanationItem(feature="packets_per_sec", value=pps, contribution=0.42, weight=38),
            ExplanationItem(feature="syn_ratio", contribution=0.31, weight=28),
            ExplanationItem(feature="unique_sources", contribution=0.22, weight=20),
            ExplanationItem(feature="flow_duration", contribution=0.15, weight=14),
        ],
        risk_score=risk,
        risk_components={
            "ml_confidence": round(100 * (0.80 + 0.19 * ramp)),
            "traffic_anomaly": round(100 * ramp),
            "attack_severity": 90,
            "source_reputation": 50,
        },
        model_version="synthetic-demo",
    )


async def demo_detections(count: int, target: str, label: str) -> int:
    redis = Redis.from_url(get_settings().redis_url)
    try:
        for index in range(count):
            detection = _demo_detection(index, count, target, label)
            await redis.xadd(
                DETECTIONS_STREAM,
                {"data": detection.model_dump_json()},
                maxlen=DEMO_STREAM_MAXLEN,
                approximate=True,
            )
    finally:
        await redis.aclose()
    print(f"Published {count} synthetic '{label}' detections targeting {target}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bootstrap", help="create the initial admin user if none exists")
    reset = commands.add_parser("reset-password", help="give a user a new generated password")
    reset.add_argument("username")
    demo = commands.add_parser(
        "demo-detections",
        help="publish synthetic detections to exercise the pipeline (not real traffic)",
    )
    demo.add_argument("--count", type=int, default=20)
    demo.add_argument(
        "--target", default="203.0.113.10", help="destination IP (default: TEST-NET-3)"
    )
    demo.add_argument("--label", default="ddos")
    args = parser.parse_args(argv)

    if args.command == "bootstrap":
        return asyncio.run(bootstrap())
    if args.command == "reset-password":
        return asyncio.run(reset_password(args.username))
    return asyncio.run(demo_detections(args.count, args.target, args.label))


if __name__ == "__main__":
    sys.exit(main())
