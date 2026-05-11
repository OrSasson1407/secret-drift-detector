.PHONY: help install lint format typecheck test test-unit test-integration \
        run-server run-agent run-ui \
        docker-build docker-up docker-down docker-logs \
        docker-dev-up docker-dev-down clean

# ── Meta ──────────────────────────────────────────────────────────────────────
help:
    @echo ""
    @echo "  Secret Drift Detector — available targets"
    @echo ""
    @echo "  Dev setup"
    @echo "    install          Install all dependencies (incl. dev)"
    @echo ""
    @echo "  Code quality"
    @echo "    lint             ruff check"
    @echo "    format           ruff format"
    @echo "    typecheck        mypy"
    @echo ""
    @echo "  Tests"
    @echo "    test             All tests"
    @echo "    test-unit        Unit tests only"
    @echo "    test-integration Integration tests only"
    @echo ""
    @echo "  Run locally"
    @echo "    run-server       FastAPI dev server (reload)"
    @echo "    run-agent        One-shot drift check"
    @echo "    run-ui           Vite dev server"
    @echo ""
    @echo "  Docker (production)"
    @echo "    docker-build     Build runtime image"
    @echo "    docker-up        Start api + agent"
    @echo "    docker-down      Stop all services"
    @echo "    docker-logs      Tail logs"
    @echo ""
    @echo "  Docker (dev — includes Vault + dummy_app)"
    @echo "    docker-dev-up    Start all services incl. dev profile"
    @echo "    docker-dev-down  Stop all"
    @echo ""
    @echo "    clean            Remove build artefacts"
    @echo ""

# ── Dev setup ─────────────────────────────────────────────────────────────────
install:
    poetry install

# ── Code quality ──────────────────────────────────────────────────────────────
lint:
    poetry run ruff check .

format:
    poetry run ruff format .

typecheck:
    poetry run mypy detector --ignore-missing-imports

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
    poetry run pytest -v --tb=short

test-unit:
    poetry run pytest tests/unit -v --tb=short

test-integration:
    poetry run pytest tests/integration -v --tb=short

# ── Run locally ───────────────────────────────────────────────────────────────
run-server:
    poetry run uvicorn detector.server.app:app --reload --port 8000

run-agent:
    poetry run detector check --config config/detector.toml

run-ui:
    cd ui && npm run dev

# ── Docker (production) ───────────────────────────────────────────────────────
docker-build:
    docker build --target runtime -t secret-drift-detector:latest .

docker-up:
    docker compose up -d api agent

docker-down:
    docker compose down

docker-logs:
    docker compose logs -f

# ── Docker (dev — Vault + dummy_app included) ─────────────────────────────────
docker-dev-up:
    docker compose --profile dev up -d --build

docker-dev-down:
    docker compose --profile dev down

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    rm -f drift_history.db
