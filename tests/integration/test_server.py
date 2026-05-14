import os
import pytest
from fastapi.testclient import TestClient

# Ensure env is set before importing app
os.environ["DRIFT_DB_PATH"] = "test_db_temp.json"
os.environ["DRIFT_API_KEY"] = "test-secret-key"

from detector.server.app import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-secret-key"}

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_list_runs_without_auth_fails():
    # Should fail because X-API-Key is missing
    response = client.get("/api/v1/runs")
    assert response.status_code == 403

def test_list_runs_with_auth_succeeds():
    # Should succeed because we pass the valid key
    response = client.get("/api/v1/runs", headers=HEADERS)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_latest_run_no_runs_yet():
    # Initially the in-memory DB is empty, should return 404 (we fixed this from 204!)
    response = client.get("/api/v1/latest")
    assert response.status_code == 404

def test_stats_endpoint():
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_runs" in data
