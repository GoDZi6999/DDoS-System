from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import APIKeyHeader
from redis.exceptions import RedisError

from app.api.deps import SessionDep
from app.core.config import get_settings
from app.models import ApiKey
from app.models.enums import ApiScope
from app.schemas.flow import DetectResponse, FlowBatch, IngestResponse
from app.services import api_keys as api_key_service
from app.services import flow_ingest
from app.services.detector import DetectorUnavailable, InvalidFlows, get_detector

router = APIRouter(tags=["v2"])

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_scope(scope: ApiScope):
    async def check(
        request: Request,
        session: SessionDep,
        key: Annotated[str | None, Depends(api_key_header)],
    ) -> ApiKey:
        if not key:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header")
        api_key = await api_key_service.authenticate(session, key)
        if api_key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")
        if scope.value not in api_key.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"API key lacks the {scope} scope")
        limit = get_settings().api_rate_per_minute
        if not await api_key_service.within_rate(request.app.state.redis, api_key.id, limit):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                headers={"Retry-After": "60"},
            )
        return api_key

    return Depends(check)


def _check_size(batch: FlowBatch) -> None:
    limit = get_settings().api_max_flows
    if len(batch.flows) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"At most {limit} flows per request")


@router.post("/detect", response_model=DetectResponse)
async def detect(
    batch: FlowBatch, _: Annotated[ApiKey, require_scope(ApiScope.DETECT)]
) -> DetectResponse:
    """Classify flows now and return a verdict per flow: label, confidence, class
    probabilities, the top SHAP reasons for attacks (up to API_MAX_EXPLAINED per
    request) and an advisory recommended action. Stateless: nothing is stored and
    no alert is raised; use POST /v2/flows for monitoring with alerts."""
    _check_size(batch)
    try:
        detector = await run_in_threadpool(get_detector)
        return await run_in_threadpool(
            detector.detect, batch.flows, get_settings().api_max_explained
        )
    except DetectorUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except InvalidFlows as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.post("/flows", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_flows(
    batch: FlowBatch,
    request: Request,
    api_key: Annotated[ApiKey, require_scope(ApiScope.INGEST)],
) -> IngestResponse:
    """Queue flows for the real-time engine, which classifies them, scores risk and
    raises alerts (dashboard, notifications, webhooks) like any capture sensor.
    Requires an engine running with `--source sensor`."""
    _check_size(batch)
    try:
        name = await flow_ingest.ingest(request.app.state.redis, api_key.prefix, batch.flows)
    except RedisError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Flow queue unavailable") from exc
    return IngestResponse(accepted=len(batch.flows), sensor=name)
