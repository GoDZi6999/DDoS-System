from fastapi import APIRouter, Request

from app.api.deps import AdminUser, AnalystUser, SessionDep, actor_for
from app.schemas.config import DetectionConfig
from app.services import detection_config

router = APIRouter(prefix="/config", tags=["config"])


@router.get("/detection", response_model=DetectionConfig)
async def get_detection_config(_: AnalystUser, session: SessionDep) -> DetectionConfig:
    return await detection_config.get_detection_config(session)


@router.put("/detection", response_model=DetectionConfig)
async def update_detection_config(
    body: DetectionConfig, admin: AdminUser, request: Request, session: SessionDep
) -> DetectionConfig:
    """Replace the detection settings. The change is audited with before/after values."""
    return await detection_config.update_detection_config(session, body, actor_for(admin, request))
