# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.2
RUN poetry config virtualenvs.in-project true

COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-interaction --no-ansi --without dev --no-root

COPY detector/ ./detector/
RUN poetry install --no-interaction --no-ansi --without dev


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Secret Drift Detector" \
      org.opencontainers.image.description="Detect config drift between expected secrets and live runtime" \
      org.opencontainers.image.source="https://github.com/you/secret-drift-detector"

# docker CLI is needed only for docker-exec probe mode; kept as optional
RUN apt-get update && apt-get install -y --no-install-recommends \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the pre-built venv from builder
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/detector /app/detector

# Copy config skeleton and entrypoint
COPY config/detector.toml.example /app/config/detector.toml.example
COPY pyproject.toml ./

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # default config path — override with -e DETECTOR_CONFIG=...
    DETECTOR_CONFIG=/app/config/detector.toml

EXPOSE 8000

# Healthcheck hits the FastAPI /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

# Default: start API server.
# Override CMD to run the agent:  docker run ... detector check
# Or watch mode:                  docker run ... detector watch
CMD ["uvicorn", "detector.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
