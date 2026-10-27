# Tripwire backend + family dashboard, for Cloud Run.
# Only the modules the backend imports are copied: no .env, no captured data.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-backend.txt .
RUN pip install --no-cache-dir -r requirements-backend.txt

COPY core/ core/
COPY backend/ backend/
COPY analysts/__init__.py analysts/common.py analysts/
COPY agent/__init__.py agent/redact.py agent/

RUN useradd --create-home tripwire
USER tripwire

CMD exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}
