# Built from the repository root: docker build -f backend/Dockerfile .
# The image carries the ML stack, the engine and the models, so POST /v2/detect
# and packet capture analysis (the capture worker) work.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/ml:/app/engine \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app/backend

RUN groupadd --system app && useradd --system --gid app --no-create-home app \
    # Uploaded captures (a named volume in docker-compose.yml inherits this owner).
    && mkdir -p /data/captures && chown app:app /data/captures

COPY ml/requirements.txt /app/ml/requirements.txt
COPY engine/requirements.txt /app/engine/requirements.txt
COPY backend/requirements.txt ./
RUN pip install -r /app/engine/requirements.txt -r requirements.txt

COPY ml/sentinel_ml /app/ml/sentinel_ml
COPY engine/sentinel_engine /app/engine/sentinel_engine
# Default model for /v2/detect (app/services/detector.py resolves it from here).
COPY models/sentinel-flow/2026.10.03 /app/models/sentinel-flow/2026.10.03
# Candidate model (opt-in with MODEL_BUNDLE), as in the engine image.
COPY models/sentinel-flow/2026.10.04 /app/models/sentinel-flow/2026.10.04

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app

ENV CAPTURE_DIR=/data/captures

USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
