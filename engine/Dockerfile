# Built from the repository root: docker build -f engine/Dockerfile .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/ml:/app/engine \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY ml/requirements.txt ml/requirements.txt
COPY engine/requirements.txt engine/requirements.txt
RUN pip install -r engine/requirements.txt

COPY ml/sentinel_ml ml/sentinel_ml
COPY engine/sentinel_engine engine/sentinel_engine
COPY models/sentinel-flow/2026.10.03 models/sentinel-flow/2026.10.03
COPY data/samples/flow_profiles.csv data/samples/flow_profiles.csv

USER app
# Default: simulated lab traffic. ENGINE_SCENARIO=demo cycles through attacks.
CMD ["sh", "-c", "exec python -m sentinel_engine run --source simulate --scenario \"${ENGINE_SCENARIO:-normal}\" --loop"]
