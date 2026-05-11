from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from detector.storage.history import History

app = FastAPI(title="Secret Drift Detector API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/metrics", make_asgi_app())

history = History()


@app.get("/api/v1/runs")
def list_runs(limit: int = 50, only_drift: bool = False):
    """List recent runs. Use only_drift=true to filter to drifting runs only."""
    return history.list_runs(limit=limit, only_drift=only_drift)


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: int):
    """Full detail for a single run including the complete drift report."""
    run = history.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


@app.get("/api/v1/trend")
def drift_trend(limit: int = 30):
    """Drift counts over the last N runs — useful for dashboard charting."""
    return history.drift_trend(limit=limit)


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}
