from fastapi import APIRouter, HTTPException, Request, status
from redis.exceptions import RedisError

from app.api.deps import ViewerUser
from app.schemas.sensor import SensorList
from app.services import sensors as sensors_service

router = APIRouter(prefix="/sensors", tags=["sensors"])


@router.get("", response_model=SensorList)
async def list_sensors(_: ViewerUser, request: Request) -> SensorList:
    """Capture sensors with their health, and the engine's backlog on their flows."""
    try:
        return await sensors_service.list_sensors(request.app.state.redis)
    except RedisError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Sensor status unavailable"
        ) from exc
