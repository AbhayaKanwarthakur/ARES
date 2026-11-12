"""SQLAlchemy persistence models for passive score records."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PostgreSQLUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EventScore(Base):
    __tablename__ = "event_scores"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", name="uq_event_scores_tenant_event"),
        Index("ix_event_scores_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    features: Mapped[dict] = mapped_column(JSONB, nullable=False)
    classification: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_classification: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    novelty_distance: Mapped[float] = mapped_column(Float, nullable=False)
    is_unknown: Mapped[bool] = mapped_column(nullable=False)
    unknown_reason: Mapped[str | None] = mapped_column(String(256))
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    probabilities: Mapped[dict] = mapped_column(JSONB, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation_reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
