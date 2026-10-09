"""packet captures uploaded for analysis, linked to the flows they produced

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = ("queued", "analyzing", "done", "failed")


def upgrade() -> None:
    allowed = ", ".join(f"'{value}'" for value in STATUSES)
    op.create_table(
        "captures",
        sa.Column("id", sa.Integer(), sa.Identity(always=False), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("stored_name", sa.String(length=64), nullable=False),
        sa.Column("file_format", sa.String(length=8), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("raise_alerts", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("uploaded_by_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_offset", sa.Double(), nullable=True),
        sa.Column("report", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(f"status IN ({allowed})", name=op.f("ck_captures_capture_status")),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"], ["users.id"], name=op.f("fk_captures_uploaded_by_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_captures")),
        sa.UniqueConstraint("stored_name", name=op.f("uq_captures_stored_name")),
    )
    op.create_index(op.f("ix_captures_status"), "captures", ["status"])
    op.add_column("network_events", sa.Column("capture_id", sa.Integer(), nullable=True))
    op.create_index(op.f("ix_network_events_capture_id"), "network_events", ["capture_id"])
    op.create_foreign_key(
        op.f("fk_network_events_capture_id_captures"),
        "network_events",
        "captures",
        ["capture_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_network_events_capture_id_captures"), "network_events", type_="foreignkey"
    )
    op.drop_index(op.f("ix_network_events_capture_id"), table_name="network_events")
    op.drop_column("network_events", "capture_id")
    op.drop_index(op.f("ix_captures_status"), table_name="captures")
    op.drop_table("captures")
