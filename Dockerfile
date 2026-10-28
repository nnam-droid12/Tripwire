# Tripwire backend + family dashboard, for Cloud Run.
# Only the modules the backend imports are copied: no .env, no captured data.
FROM python:3.12-slim

# /tmp is the only writable place on Cloud Run (dry-run SMS outbox, scratch files)
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TRIPWIRE_RUNTIME_DIR=/tmp/tripwire
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-backend.txt .
RUN pip install --no-cache-dir -r requirements-backend.txt

COPY core/ core/
COPY backend/ backend/
COPY analysts/ analysts/
COPY agent/ agent/
# Margaret's laptop in the web arena: fictional pages and their rendered frames
COPY eval/__init__.py eval/
COPY eval/scenarios/pages/ eval/scenarios/pages/
COPY eval/scenarios/frames/ eval/scenarios/frames/
# evaluation results shown on the landing page and the build dashboard
COPY eval/results/ eval/results/

RUN useradd --create-home tripwire
USER tripwire

CMD exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}
