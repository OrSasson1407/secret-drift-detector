.PHONY: test lint run-ui run-server

test:
    poetry run pytest tests/unit

lint:
    poetry run ruff check .
    poetry run mypy detector

run-server:
    poetry run uvicorn detector.server.app:app --reload --port 8000

run-ui:
    cd ui && npm run dev
