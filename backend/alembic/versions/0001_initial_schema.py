"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = ("admin", "analyst", "viewer")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE")
EVENT_SOURCES = ("live", "pcap", "sim")


def _one_of(column: str, values: tuple[str, ...], name: str) -> sa.CheckConstraint:
    allowed = ", ".join(f"'{value}'" for value in values)
    return sa.CheckConstraint(f"{column} IN ({allowed})", name=op.f(name))


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _updated_at() -> sa.Column:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), sa.Identity(always=False), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("token_version", sa.Integer(), server_default="0", nullable=False),
        _created_at(),
        _updated_at(),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        _one_of("role", ROLES, "ck_users_user_role"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        _created_at(),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"])
    op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"])

    op.create_table(
        "network_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("stream_id", sa.String(length=32), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", postgresql.INET(), nullable=False),
        sa.Column("dst_ip", postgresql.INET(), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("packet_count", sa.BigInteger(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("duration", sa.Double(), nullable=False),
        sa.Column("packets_per_sec", sa.Double(), nullable=False),
        sa.Column("bytes_per_sec", sa.Double(), nullable=False),
        sa.Column("features", postgresql.JSONB(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        _one_of("source", EVENT_SOURCES, "ck_network_events_event_source"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_events")),
        sa.UniqueConstraint("stream_id", name=op.f("uq_network_events_stream_id")),
    )
    op.create_index("ix_network_events_dst_ip_ts", "network_events", ["dst_ip", "ts"])
    op.create_index(op.f("ix_network_events_ts"), "network_events", ["ts"])

    op.create_table(
        "predictions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Double(), nullable=False),
        sa.Column("class_probs", postgresql.JSONB(), nullable=False),
        sa.Column("explanation", postgresql.JSONB(), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=False),
        sa.Column("risk_components", postgresql.JSONB(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        _created_at(),
        _one_of("severity", SEVERITIES, "ck_predictions_prediction_severity"),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["network_events.id"],
            name=op.f("fk_predictions_event_id_network_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_predictions")),
        sa.UniqueConstraint("event_id", name=op.f("uq_predictions_event_id")),
    )
    op.create_index(op.f("ix_predictions_label"), "predictions", ["label"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), sa.Identity(always=False), nullable=False),
        _created_at(),
        _updated_at(),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attack_type", sa.String(length=32), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("confidence", sa.Double(), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("detection_count", sa.Integer(), nullable=False),
        sa.Column("peak_packets_per_sec", sa.Double(), nullable=False),
        sa.Column("peak_bytes_per_sec", sa.Double(), nullable=False),
        sa.Column("explanation", postgresql.JSONB(), nullable=False),
        sa.Column("risk_components", postgresql.JSONB(), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("assigned_to_id", sa.Integer(), nullable=True),
        sa.Column("acknowledged_by_id", sa.Integer(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        _one_of("severity", SEVERITIES, "ck_alerts_alert_severity"),
        _one_of("status", ALERT_STATUSES, "ck_alerts_alert_status"),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_id"], ["users.id"], name=op.f("fk_alerts_acknowledged_by_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_id"], ["users.id"], name=op.f("fk_alerts_assigned_to_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    op.create_index("ix_alerts_correlation", "alerts", ["attack_type", "destination_ip", "status"])
    op.create_index("ix_alerts_status_last_seen_at", "alerts", ["status", "last_seen_at"])

    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_events_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["network_events.id"],
            name=op.f("fk_alert_events_event_id_network_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id", name=op.f("pk_alert_events")),
    )
    op.create_index(op.f("ix_alert_events_event_id"), "alert_events", ["event_id"])

    op.create_table(
        "alert_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("author_id", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_notes_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["author_id"], ["users.id"], name=op.f("fk_alert_notes_author_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_notes")),
    )
    op.create_index(op.f("ix_alert_notes_alert_id"), "alert_notes", ["alert_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column(
            "ts", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=True),
        sa.Column("entity_id", sa.String(length=64), nullable=True),
        sa.Column("before", postgresql.JSONB(), nullable=True),
        sa.Column("after", postgresql.JSONB(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_audit_logs_actor_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"])
    op.create_index(op.f("ix_audit_logs_actor_id"), "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_entity", "audit_logs", ["entity_type", "entity_id"])
    op.create_index(op.f("ix_audit_logs_ts"), "audit_logs", ["ts"])

    # The audit log is append-only: reject UPDATE, DELETE and TRUNCATE for
    # every role. Disabling the trigger requires table ownership, which the
    # application's database role does not have.
    op.execute(
        """
        CREATE FUNCTION audit_logs_reject_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only: % is not allowed', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_change()"
    )
    op.execute(
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_change()"
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("updated_by_id", sa.Integer(), nullable=True),
        _updated_at(),
        sa.ForeignKeyConstraint(
            ["updated_by_id"], ["users.id"], name=op.f("fk_settings_updated_by_id_users")
        ),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_settings")),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.execute("DROP TRIGGER audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER audit_logs_append_only ON audit_logs")
    op.execute("DROP FUNCTION audit_logs_reject_change()")
    op.drop_table("audit_logs")
    op.drop_table("alert_notes")
    op.drop_table("alert_events")
    op.drop_table("alerts")
    op.drop_table("predictions")
    op.drop_table("network_events")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
