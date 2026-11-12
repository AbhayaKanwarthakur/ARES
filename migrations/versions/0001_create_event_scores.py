"""Create tenant-scoped passive score storage.

Revision ID: 0001_event_scores
Revises:
Create Date: 2026-11-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_event_scores"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "event_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("classification", sa.String(length=128), nullable=False),
        sa.Column("raw_classification", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("novelty_distance", sa.Float(), nullable=False),
        sa.Column("is_unknown", sa.Boolean(), nullable=False),
        sa.Column("unknown_reason", sa.String(length=256), nullable=True),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("probabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("recommendation", sa.String(length=64), nullable=False),
        sa.Column("recommendation_reason", sa.String(length=1024), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_event_scores"),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_event_scores_tenant_event"),
    )
    op.create_index(
        "ix_event_scores_tenant_created", "event_scores", ["tenant_id", "created_at"], unique=False)


def downgrade():
    op.drop_index("ix_event_scores_tenant_created", table_name="event_scores")
    op.drop_table("event_scores")
