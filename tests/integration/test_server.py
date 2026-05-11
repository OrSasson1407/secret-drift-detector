"""
Integration tests for the FastAPI server endpoints.
Uses httpx TestClient — no network calls required.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from detector.storage.history import History, RunSummary


_MOCK_RUNS = [
    RunSummary(id=2, timestamp="2024-03-15T14:32:01", expected_count=5,
               actual_count=4, drift_count=2, has_drift=True,
               max_severity="critical", sources=["vault:app"], targets=["docker:web"]),
    RunSummary(id=1, timestamp="2024-03-15T13:00:00", expected_count=5,
               actual_count=5, drift_count=0, has_drift=False,
               max_severity=None, sources=["vault:app"], targets=["docker:web"]),
]

_MOCK_RUN_DETAIL = {
    "id": 2, "timestamp": "2024-03-15T14:32:01",
    "expected_count": 5, "actual_count": 4,
    "has_drift": 1, "drift_count": 2, "max_severity": "critical",
    "sources": ["vault:app"], "targets": ["docker:web"],
    "report_json": {"items": [], "expected_count": 5, "actual_count": 4,
                    "checked_at": "2024-03-15T14:32:01Z", "sources": [], "targets": []},
}

_MOCK_TREND = [
    {"id": 1, "timestamp": "2024-03-15T13:00:00", "drift_count": 0, "has_drift": 0, "max_severity": None},
    {"id": 2, "timestamp": "2024-03-15T14:32:01", "drift_count": 2, "has_drift": 1, "max_severity": "critical"},
]


@pytest.fixture
def client():
    from detector.server.app import app
    return TestClient(app)


@pytest.fixture(autouse=True)
def mock_history():
    with patch.object(History, "list_runs",   return_value=_MOCK_RUNS), \
         patch.object(History, "get_run",     return_value=_MOCK_RUN_DETAIL), \
         patch.object(History, "drift_trend", return_value=_MOCK_TREND):
        yield


def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_runs(client):
    r = client.get("/api/v1/runs")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    assert data[0]["id"] == 2


def test_list_runs_only_drift(client):
    r = client.get("/api/v1/runs?only_drift=true")
    assert r.status_code == 200


def test_get_run(client):
    r = client.get("/api/v1/runs/2")
    assert r.status_code == 200
    assert r.json()["id"] == 2
    assert "report_json" in r.json()


def test_get_run_not_found(client):
    with patch.object(History, "get_run", return_value=None):
        r = client.get("/api/v1/runs/9999")
    assert r.status_code == 404


def test_drift_trend(client):
    r = client.get("/api/v1/trend")
    assert r.status_code == 200
    trend = r.json()
    assert len(trend) == 2
    assert trend[0]["id"] < trend[1]["id"]
