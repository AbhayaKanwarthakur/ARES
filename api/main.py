"""Passive, authenticated API for authorized website-backend event windows."""
import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from agent.detector import MODEL_PATH, get_detector
from agent.runtime_mode import get_runtime_mode
from agent.settings import load_settings
from api.auth import ApiClient, load_api_clients, require_api_client
from api.config import ApiSettings
from api.database import get_engine, get_session
from api.models import EventScore
from api.schemas import ScoreRequest, ScoreResponse
from api.scoring import score_features

logger = logging.getLogger("ares.api")
_MAX_REQUEST_BYTES = 16_384


class BodyLimitMiddleware:
    """Buffer only bounded API requests, including chunked request bodies."""

    def __init__(self, app, max_bytes=_MAX_REQUEST_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", ())
        content_lengths = [value for name, value in raw_headers if name == b"content-length"]
        transfer_encodings = [value for name, value in raw_headers if name == b"transfer-encoding"]
        content_encodings = [value.lower() for name, value in raw_headers if name == b"content-encoding"]
        if len(content_lengths) > 1 or (content_lengths and transfer_encodings):
            await self._reject(send, 400, "Ambiguous request framing.")
            return
        if content_encodings and any(value != b"identity" for value in content_encodings):
            await self._reject(send, 415, "Compressed request bodies are not supported.")
            return

        content_length = content_lengths[0] if content_lengths else None
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length.")
                return
            if declared_length < 0:
                await self._reject(send, 400, "Invalid Content-Length.")
                return
            if declared_length > self.max_bytes:
                await self._reject(send, 413, "Request body exceeds the allowed size.")
                return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._reject(send, 413, "Request body exceeds the allowed size.")
                return
            more_body = message.get("more_body", False)

        replayed = False

        async def replay_body():
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)

    @staticmethod
    async def _reject(send, code, message):
        payload = json.dumps({"detail": message}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": code,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
        })
        await send({"type": "http.response.body", "body": payload})


@asynccontextmanager
async def lifespan(app):
    runtime_mode = get_runtime_mode()
    if runtime_mode != "production":
        logger.warning("API running in %s mode. For production use set ARES_RUNTIME_MODE=production.", runtime_mode)
    settings = ApiSettings.from_env()
    if not Path(MODEL_PATH).is_file():
        raise RuntimeError(f"Detector model is missing: {MODEL_PATH}")
    app.state.api_clients = load_api_clients(settings.api_keys_file)
    app.state.agent_settings = load_settings()
    app.state.model_version = hashlib.sha256(Path(MODEL_PATH).read_bytes()).hexdigest()
    get_detector()
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    logger.info("Passive scoring API started in %s mode with %d authorized client(s).", runtime_mode, len(app.state.api_clients))
    yield


app = FastAPI(
    title="Adaptive Security Agent Scoring API",
    version="1.0.0",
    description="Passive scoring of bounded, pre-aggregated event features for authorized website backends.",
    docs_url="/docs" if os.environ.get("ARES_ENABLE_API_DOCS", "false").lower() == "true" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.environ.get("ARES_ENABLE_API_DOCS", "false").lower() == "true" else None,
    lifespan=lifespan,
)
app.add_middleware(BodyLimitMiddleware)


@app.get("/health/live", include_in_schema=False)
def live():
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
def ready():
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        get_detector().fresh()
    except (OSError, RuntimeError, SQLAlchemyError) as error:
        logger.error("Readiness check failed: %s", error.__class__.__name__)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Scoring service is not ready.") from error
    return {"status": "ready"}


@app.post("/v1/windows/score", response_model=ScoreResponse, status_code=status.HTTP_200_OK)
def score_window(
    payload: ScoreRequest,
    request: Request,
    client: ApiClient = Depends(require_api_client),
    session: Session = Depends(get_session),
):
    result = score_features(payload.features.model_dump(), request.app.state.agent_settings)
    values = {
        "tenant_id": client.tenant_id,
        "event_id": payload.event_id,
        "features": payload.features.model_dump(mode="json"),
        "classification": result["classification"],
        "raw_classification": result["raw_classification"],
        "confidence": result["confidence"],
        "novelty_distance": result["novelty_distance"],
        "is_unknown": result["is_unknown"],
        "unknown_reason": result["unknown_reason"],
        "risk": result["risk"],
        "risk_score": result["risk_score"],
        "probabilities": result["probabilities"],
        "recommendation": result["recommendation"],
        "recommendation_reason": result["recommendation_reason"],
        "model_version": request.app.state.model_version,
    }

    statement = (
        insert(EventScore)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["tenant_id", "event_id"])
        .returning(EventScore.id)
    )
    inserted_id = session.execute(statement).scalar_one_or_none()
    duplicate = inserted_id is None
    if duplicate:
        record = session.execute(
            select(EventScore).where(
                EventScore.tenant_id == client.tenant_id,
                EventScore.event_id == payload.event_id,
            )
        ).scalar_one()
    else:
        record = session.execute(
            select(EventScore).where(EventScore.id == inserted_id)
        ).scalar_one()
    session.commit()

    if not duplicate:
        logger.info("Scored event window for tenant %s.", client.tenant_id)
    return ScoreResponse(
        event_id=record.event_id,
        duplicate=duplicate,
        classification=record.classification,
        raw_classification=record.raw_classification,
        confidence=record.confidence,
        novelty_distance=record.novelty_distance,
        is_unknown=record.is_unknown,
        unknown_reason=record.unknown_reason,
        risk=record.risk,
        risk_score=record.risk_score,
        recommendation=record.recommendation,
        recommendation_reason=record.recommendation_reason,
        model_version=record.model_version,
    )
