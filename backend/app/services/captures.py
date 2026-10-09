"""Uploaded packet captures: storage, the analysis queue, and alert evidence.

Files are stored in CAPTURE_DIR under a random name; the original file name is
only displayed. Analysis runs in the capture worker (app/workers/capture_analyzer.py),
which claims queued captures with SELECT ... FOR UPDATE SKIP LOCKED.
"""

import contextlib
import hashlib
import os
import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import Alert, Capture, NetworkEvent, alert_events
from app.models.enums import CaptureStatus
from app.services.audit import Actor, record_audit
from app.services.capture_analysis import FlowKey, file_format
from app.services.errors import ConflictError, NotFoundError, UnprocessableError

# Flows of one alert considered for its evidence file (newest first).
EVIDENCE_MAX_FLOWS = 5000
EVIDENCE_MAX_PACKETS = 50_000
_UNSAFE_NAME = re.compile(r"[^\w.\- ()\[\]]+")


class CaptureTooLarge(Exception):
    pass


def capture_dir(settings: Settings) -> Path:
    path = Path(settings.capture_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def capture_path(settings: Settings, capture: Capture) -> Path:
    return Path(settings.capture_dir) / capture.stored_name


def display_name(filename: str) -> str:
    """The client's file name, reduced to a harmless label."""
    name = _UNSAFE_NAME.sub("_", Path(filename.replace("\\", "/")).name).strip(" .")
    return name[:255] or "capture"


async def store_upload(
    session: AsyncSession,
    settings: Settings,
    chunks: AsyncIterator[bytes],
    filename: str,
    raise_alerts: bool,
    actor: Actor,
) -> Capture:
    """Stream an upload to disk, check it is a pcap/pcapng file and queue it."""
    limit = settings.capture_max_mb * 1024 * 1024
    folder = capture_dir(settings)
    token = secrets.token_hex(16)
    partial = folder / f".upload-{token}"
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        with partial.open("wb") as fh:
            async for chunk in chunks:
                size += len(chunk)
                if size > limit:
                    raise CaptureTooLarge(f"Captures are limited to {settings.capture_max_mb} MB")
                if len(head) < 4:
                    head += chunk[: 4 - len(head)]
                digest.update(chunk)
                fh.write(chunk)
        fmt = file_format(head)
        if fmt is None:
            raise UnprocessableError(
                "Not a packet capture: expected a .pcap or .pcapng file (in Wireshark: "
                "File > Save As, Wireshark/tcpdump - pcap or pcapng)"
            )
        stored = folder / f"{token}.{fmt}"
        os.replace(partial, stored)
    finally:
        with contextlib.suppress(FileNotFoundError):
            partial.unlink()

    capture = Capture(
        filename=display_name(filename),
        stored_name=stored.name,
        file_format=fmt,
        size_bytes=size,
        sha256=digest.hexdigest(),
        raise_alerts=raise_alerts,
        status=CaptureStatus.QUEUED,
        uploaded_by_id=actor.user_id,
    )
    session.add(capture)
    await session.flush()
    record_audit(
        session,
        actor,
        "capture.uploaded",
        entity_type="capture",
        entity_id=capture.id,
        after={
            "filename": capture.filename,
            "size_bytes": size,
            "sha256": capture.sha256,
            "raise_alerts": raise_alerts,
        },
    )
    await session.commit()
    return capture


async def list_captures(
    session: AsyncSession, limit: int, offset: int
) -> tuple[list[Capture], int]:
    total = await session.scalar(select(func.count()).select_from(Capture))
    rows = await session.scalars(
        select(Capture).order_by(Capture.id.desc()).limit(limit).offset(offset)
    )
    return list(rows), total or 0


async def get_capture(session: AsyncSession, capture_id: int) -> Capture:
    capture = await session.get(Capture, capture_id)
    if capture is None:
        raise NotFoundError("Capture not found")
    return capture


async def delete_capture(
    session: AsyncSession, settings: Settings, capture_id: int, actor: Actor
) -> None:
    """Delete the file and its record. Flows and alerts it produced are kept."""
    capture = await session.get(Capture, capture_id, with_for_update=True)
    if capture is None:
        raise NotFoundError("Capture not found")
    if capture.status == CaptureStatus.ANALYZING:
        raise ConflictError("The capture is being analysed; delete it when analysis ends")
    record_audit(
        session,
        actor,
        "capture.deleted",
        entity_type="capture",
        entity_id=capture.id,
        before={"filename": capture.filename, "sha256": capture.sha256},
    )
    path = capture_path(settings, capture)
    await session.delete(capture)
    await session.commit()
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


# --- worker side ---------------------------------------------------------------


async def claim_next(session: AsyncSession) -> Capture | None:
    """Mark the oldest queued capture as analysing and return it (committed)."""
    capture = await session.scalar(
        select(Capture)
        .where(Capture.status == CaptureStatus.QUEUED)
        .order_by(Capture.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if capture is None:
        await session.rollback()
        return None
    capture.status = CaptureStatus.ANALYZING
    capture.started_at = datetime.now(UTC)
    await session.commit()
    return capture


async def finish(
    session: AsyncSession,
    capture_id: int,
    *,
    report: dict | None = None,
    time_offset: float | None = None,
    error: str | None = None,
) -> None:
    await session.execute(
        update(Capture)
        .where(Capture.id == capture_id)
        .values(
            status=CaptureStatus.FAILED if error else CaptureStatus.DONE,
            error=error[:2000] if error else None,
            report=report,
            time_offset=time_offset,
            finished_at=datetime.now(UTC),
        )
    )
    await session.commit()


async def fail_interrupted(session: AsyncSession) -> int:
    """Captures left 'analyzing' by a stopped worker. Re-running them could
    duplicate the flows already sent, so they are failed with a clear reason."""
    result = await session.execute(
        update(Capture)
        .where(Capture.status == CaptureStatus.ANALYZING)
        .values(
            status=CaptureStatus.FAILED,
            error="Analysis was interrupted (the capture worker restarted); upload the file again",
            finished_at=datetime.now(UTC),
        )
    )
    await session.commit()
    return result.rowcount or 0


# --- alert evidence --------------------------------------------------------------


async def evidence_capture_id(session: AsyncSession, alert_id: int) -> int | None:
    """The uploaded capture most of the alert's flows came from, if any."""
    return await session.scalar(
        select(NetworkEvent.capture_id)
        .join(alert_events, alert_events.c.event_id == NetworkEvent.id)
        .join(Capture, Capture.id == NetworkEvent.capture_id)
        .where(alert_events.c.alert_id == alert_id, Capture.status == CaptureStatus.DONE)
        .group_by(NetworkEvent.capture_id)
        .order_by(func.count().desc(), NetworkEvent.capture_id.desc())
        .limit(1)
    )


@dataclass
class EvidenceRequest:
    capture: Capture
    path: Path
    flows: list[FlowKey]


async def evidence_request(
    session: AsyncSession, settings: Settings, alert_id: int
) -> EvidenceRequest:
    if await session.get(Alert, alert_id) is None:
        raise NotFoundError("Alert not found")
    capture_id = await evidence_capture_id(session, alert_id)
    capture = await session.get(Capture, capture_id) if capture_id else None
    path = capture_path(settings, capture) if capture else None
    if capture is None or path is None or not path.is_file():
        raise UnprocessableError(
            "No packets are stored for this alert. Packet evidence is kept for alerts "
            "raised from uploaded captures; use the Wireshark filter on your own capture."
        )
    rows = await session.execute(
        select(
            NetworkEvent.ts,
            NetworkEvent.duration,
            NetworkEvent.src_ip,
            NetworkEvent.dst_ip,
            NetworkEvent.src_port,
            NetworkEvent.dst_port,
            NetworkEvent.protocol,
        )
        .join(alert_events, alert_events.c.event_id == NetworkEvent.id)
        .where(alert_events.c.alert_id == alert_id, NetworkEvent.capture_id == capture.id)
        .order_by(NetworkEvent.ts.desc())
        .limit(EVIDENCE_MAX_FLOWS)
    )
    offset = timedelta(seconds=capture.time_offset or 0.0)
    flows = []
    for ts, duration, src, dst, sport, dport, protocol in rows.all():
        end = (ts - offset).timestamp()
        flows.append(
            FlowKey(
                str(src), str(dst), sport or 0, dport or 0, protocol, end - (duration or 0.0), end
            )
        )
    return EvidenceRequest(capture, path, flows)


def wireshark_filter(alert: Alert) -> str:
    """A Wireshark display filter for the alert's traffic."""
    src, dst = str(alert.source_ip), str(alert.destination_ip)
    src_field = "ipv6" if ip_address(src).version == 6 else "ip"
    dst_field = "ipv6" if ip_address(dst).version == 6 else "ip"
    proto = alert.protocol if alert.protocol in ("tcp", "udp") else None
    port = alert.destination_port
    if alert.attack_type == "portscan":
        return f"{src_field}.src == {src} && {dst_field}.dst == {dst} && tcp.flags.syn == 1"
    if alert.attack_type in ("ddos", "dos"):
        # Floods come from many sources: filter on the target.
        target = f"{dst_field}.dst == {dst}"
        return f"{target} && {proto}.dstport == {port}" if proto and port else target
    pair = f"{src_field}.addr == {src} && {dst_field}.addr == {dst}"
    return f"{pair} && {proto}.port == {port}" if proto and port else pair
