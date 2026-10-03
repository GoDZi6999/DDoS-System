"""Detection settings, stored as one JSON document in the settings table."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting
from app.schemas.config import DetectionConfig
from app.services.audit import Actor, record_audit

SETTING_KEY = "detection"


async def get_detection_config(session: AsyncSession) -> DetectionConfig:
    row = await session.get(Setting, SETTING_KEY)
    return DetectionConfig() if row is None else DetectionConfig.model_validate(row.value)


async def update_detection_config(
    session: AsyncSession, config: DetectionConfig, actor: Actor
) -> DetectionConfig:
    row = await session.get(Setting, SETTING_KEY, with_for_update=True)
    before = DetectionConfig() if row is None else DetectionConfig.model_validate(row.value)
    value = config.model_dump(mode="json")
    if row is None:
        session.add(Setting(key=SETTING_KEY, value=value, updated_by_id=actor.user_id))
    else:
        row.value = value
        row.updated_by_id = actor.user_id
    record_audit(
        session,
        actor,
        "config.updated",
        entity_type="setting",
        entity_id=SETTING_KEY,
        before=before.model_dump(mode="json"),
        after=value,
    )
    await session.commit()
    return config
