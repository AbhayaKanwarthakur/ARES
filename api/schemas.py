"""Strict, bounded request and response models for website event-window scoring."""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EventFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    destination_port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP", "HTTP", "SSH"]
    packets_per_second: float = Field(ge=0, le=10_000_000)
    failed_login_count: int = Field(ge=0, le=1_000_000)
    request_count: int = Field(ge=1, le=10_000_000)
    payload_length: float = Field(ge=0, le=1_000_000)
    connection_duration: float = Field(ge=0, le=86_400)
    unusual_port: float = Field(ge=0, le=1)
    login_frequency: float = Field(ge=0, le=1_000_000)
    special_char_ratio: float = Field(ge=0, le=1)
    distinct_ports: int = Field(ge=1, le=65535)


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: UUID
    features: EventFeatures


class ScoreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    duplicate: bool
    classification: str
    raw_classification: str
    confidence: float
    novelty_distance: float
    is_unknown: bool
    unknown_reason: str | None
    risk: str
    risk_score: float
    recommendation: str
    recommendation_reason: str
    model_version: str
