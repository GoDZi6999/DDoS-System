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

COPY ml/argus_ml ml/argus_ml
COPY engine/argus_engine engine/argus_engine
COPY models/argus-flow/2026.10.03 models/argus-flow/2026.10.03
# Candidate model (opt-in with MODEL_BUNDLE); see ml/reports/2026.10.04.
COPY models/argus-flow/2026.10.04 models/argus-flow/2026.10.04
COPY data/samples/flow_profiles.csv data/samples/flow_profiles.csv

USER app
# Default: simulated lab traffic. ENGINE_SCENARIO=demo cycles through attacks.
CMD ["sh", "-c", "exec python -m argus_engine run --source simulate --scenario \"${ENGINE_SCENARIO:-normal}\" --loop"]
