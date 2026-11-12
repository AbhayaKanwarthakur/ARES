FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ARES_MODEL_PATH=/app/models/api-detector.joblib \
    ARES_DATA_PATH=/app/data/attacks.csv \
    ARES_API_KEYS_FILE=/run/secrets/api_keys.json \
    ARES_ENABLE_API_DOCS=false

WORKDIR /app

COPY requirements-api.txt ./
RUN pip install --no-cache-dir -r requirements-api.txt \
    && groupadd --system --gid 10001 ares \
    && useradd --system --uid 10001 --gid ares --home-dir /app ares

COPY --chown=ares:ares agent ./agent
COPY --chown=ares:ares api ./api
COPY --chown=ares:ares alembic.ini ./
COPY --chown=ares:ares migrations ./migrations
COPY --chown=ares:ares config ./config
COPY --chown=ares:ares data/attacks.csv ./data/attacks.csv
COPY --chown=ares:ares models/api-detector.joblib ./models/api-detector.joblib

USER 10001:10001
EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 1 --limit-concurrency 100 --timeout-keep-alive 5"]
