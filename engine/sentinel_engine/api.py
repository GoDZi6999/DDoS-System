"""Analysis API: ArgusAI detection as a service for other applications.

    POST /v1/analyze        flow records (JSON) -> one verdict per flow + rule detections
    POST /v1/analyze/pcap   a capture (Wireshark .pcapng, tcpdump .pcap) -> attack report
    GET  /health            liveness and model version (no key needed)

Callers authenticate with an `X-API-Key` header. Only SHA-256 hashes of the
keys are configured (`ARGUS_API_KEYS="name:hash,..."`; create one with
`python -m sentinel_engine api-key --name <tenant>`), and the key's name is
the tenant echoed in every response. Requests are rate-limited per key, and
bodies are size-limited. Analysis is stateless: nothing is stored, nothing
is published to the dashboard, and nothing is blocked. Recommended actions
are advisory.

Run: `python -m sentinel_engine serve` (OpenAPI docs at /docs).
"""

import hashlib
import hmac
import secrets
import tempfile
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sentinel_ml.inference import Predictor

from sentinel_engine import analysis
from sentinel_engine.flowstream import parse_record

MAX_FLOWS = 10_000
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_DETECTIONS = 1_000
RATE_PER_MINUTE = 60
CHUNK = 1 << 20


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_key() -> tuple[str, str]:
    """A random API key and the hash to configure for it."""
    key = "argus_" + secrets.token_urlsafe(32)
    return key, hash_key(key)


def parse_keys(spec: str) -> dict[str, str]:
    """`name:sha256hex,...` -> {hash: name}."""
    keys = {}
    for item in filter(None, (part.strip() for part in spec.split(","))):
        name, _, digest = item.partition(":")
        if not name or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"invalid API key entry {item!r}: expected name:sha256hex")
        keys[digest] = name
    return keys


class RateLimiter:
    """Sliding one-minute window per tenant."""

    def __init__(self, per_minute: int, clock=time.monotonic) -> None:
        self.per_minute = per_minute
        self.clock = clock
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def retry_after(self, tenant: str) -> int:
        """0 when the call may proceed (and is counted), else seconds to wait."""
        now = self.clock()
        with self._lock:
            calls = self._calls[tenant]
            while calls and calls[0] <= now - 60:
                calls.popleft()
            if len(calls) >= self.per_minute:
                return max(int(calls[0] + 60 - now) + 1, 1)
            calls.append(now)
            return 0


class AnalyzeRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=MAX_FLOWS,
        description="Flow records in the capture sensors' format (flows.Flow.record()): "
        "src_ip, dst_ip, src_port, dst_port, protocol, start, end (epoch seconds), "
        "packet_count, byte_count, duration and the 37 `features`.",
    )


def create_app(
    predictor: Predictor,
    keys: dict[str, str],
    rate_per_minute: int = RATE_PER_MINUTE,
    max_upload_bytes: int = MAX_UPLOAD_BYTES,
) -> FastAPI:
    if not keys:
        raise ValueError("no API keys configured (ARGUS_API_KEYS); refusing to run without auth")
    app = FastAPI(
        title="ArgusAI Analysis API",
        version="1",
        description="Classify network flows or packet captures with ArgusAI's detection "
        "pipeline. Advisory only: nothing is stored or blocked.",
    )
    limiter = RateLimiter(rate_per_minute)
    # SHAP's explainer and the flow builder are not shared safely across
    # threads; analyses are short, so they run one at a time.
    lock = threading.Lock()
    model_version = "{name}-{version}".format(**predictor.bundle.metadata)

    def tenant(x_api_key: Annotated[str | None, Header()] = None) -> str:
        digest = hash_key(x_api_key or "")
        name = next((n for h, n in keys.items() if hmac.compare_digest(h, digest)), None)
        if x_api_key is None or name is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "missing or invalid X-API-Key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        wait = limiter.retry_after(name)
        if wait:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"rate limit of {rate_per_minute} requests per minute exceeded",
                headers={"Retry-After": str(wait)},
            )
        return name

    def locked(fn, *args):
        with lock:
            return fn(*args)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "model_version": model_version}

    @app.post("/v1/analyze")
    async def analyze(body: AnalyzeRequest, who: Annotated[str, Depends(tenant)]) -> dict:
        """One detection per flow (`flow_index` = position in `flows`), in input order,
        followed by rule detections (port scans, beaconing) found across the batch."""
        records, invalid = [], []
        for i, raw in enumerate(body.flows):
            record = parse_record(raw)
            if record is None:
                invalid.append(i)
            records.append(record)
        if invalid:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                {"message": "invalid flow records", "flow_indexes": invalid[:100]},
            )
        report = await run_in_threadpool(locked, analysis.analyze_records, predictor, records)
        return {"tenant": who, "summary": report.summary(), "detections": report.detections}

    @app.post("/v1/analyze/pcap")
    async def analyze_pcap(
        who: Annotated[str, Depends(tenant)],
        capture: Annotated[UploadFile, File(description="A .pcap or .pcapng capture")],
        include_benign: Annotated[bool, Query()] = False,
    ) -> dict:
        """Builds flows from the capture's packets (original timestamps kept) and
        returns the summary and the detections (attacks only unless
        `include_benign`), each with a Wireshark display filter."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture"
            size = 0
            with path.open("wb") as out:
                while chunk := await capture.read(CHUNK):
                    size += len(chunk)
                    if size > max_upload_bytes:
                        raise HTTPException(
                            status.HTTP_413_CONTENT_TOO_LARGE,
                            f"capture larger than {max_upload_bytes // (1024 * 1024)} MB",
                        )
                    out.write(chunk)
            with path.open("rb") as handle:
                magic = handle.read(4)
            if magic not in PCAP_MAGICS:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "not a pcap or pcapng capture"
                )
            try:
                report = await run_in_threadpool(locked, analysis.analyze_capture, predictor, path)
            except Exception as exc:  # truncated or corrupt captures
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, f"could not read the capture: {exc}"
                ) from exc
        detections = report.detections if include_benign else report.attacks
        return {
            "tenant": who,
            "summary": report.summary(),
            "detections": detections[:MAX_DETECTIONS],
            "truncated": len(detections) > MAX_DETECTIONS,
        }

    return app


PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),  # pcap, little-endian, microseconds
    bytes.fromhex("a1b2c3d4"),  # pcap, big-endian
    bytes.fromhex("4d3cb2a1"),  # pcap, little-endian, nanoseconds
    bytes.fromhex("a1b23c4d"),  # pcap, big-endian, nanoseconds
    bytes.fromhex("0a0d0d0a"),  # pcapng section header (Wireshark's default)
}
