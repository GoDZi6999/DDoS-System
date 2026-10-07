"""notification channels and delivery outbox

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CHANNEL_KINDS = ("email", "slack", "webhook")
EVENTS = ("alert.created", "alert.escalated", "test")
STATUSES = ("pending", "sent", "failed", "suppressed")


def _one_of(column: str, values: tuple[str, ...], name: str) -> sa.CheckConstraint:
    allowed = ", ".join(f"'{value}'" for value in values)
    return sa.CheckConstraint(f"{column} IN ({allowed})", name=op.f(name))


def _now(name: str) -> sa.Column:
    return sa.Column(
        name, sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), sa.Identity(always=False), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("min_severity", sa.String(length=32), nullable=False),
        sa.Column("max_per_hour", sa.SmallInteger(), server_default="30", nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        _now("created_at"),
        _now("updated_at"),
        _one_of("kind", CHANNEL_KINDS, "ck_notification_channels_channel_kind"),
        _one_of("min_severity", SEVERITIES, "ck_notification_channels_channel_min_severity"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_notification_channels_created_by_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_channels")),
        sa.UniqueConstraint("name", name=op.f("uq_notification_channels_name")),
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("channel_id", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=True),
        sa.Column("event", sa.String(length=32), nullable=False),
        sa.Column("dedupe_key", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.SmallInteger(), server_default="0", nullable=False),
        _now("next_attempt_at"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        _now("created_at"),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        _one_of("event", EVENTS, "ck_notification_deliveries_delivery_event"),
        _one_of("status", STATUSES, "ck_notification_deliveries_delivery_status"),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_notification_deliveries_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["channel_id"],
            ["notification_channels.id"],
            name=op.f("fk_notification_deliveries_channel_id_notification_channels"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_deliveries")),
        sa.UniqueConstraint(
            "channel_id", "dedupe_key", name=op.f("uq_notification_deliveries_channel_id")
        ),
    )
    op.create_index(
        op.f("ix_notification_deliveries_alert_id"), "notification_deliveries", ["alert_id"]
    )
    op.create_index(
        op.f("ix_notification_deliveries_created_at"), "notification_deliveries", ["created_at"]
    )
    op.create_index(
        "ix_notification_deliveries_due", "notification_deliveries", ["status", "next_attempt_at"]
    )


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_table("notification_channels")
