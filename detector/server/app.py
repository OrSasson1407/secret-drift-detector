import asyncio
import json as _json
import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from prometheus_client import make_asgi_app

from detector.diff.models import Severity
from detector.storage.history import History
from detector.storage.snapshot import Storage

app = FastAPI(title="Secret Drift Detector API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/metrics", make_asgi_app())

# Resolve db path from env so docker / CI can override without code changes
_DB_PATH = os.environ.get("DRIFT_DB_PATH", "drift_history.db")
history  = History(db_path=_DB_PATH)
storage  = Storage(db_path=_DB_PATH)


# ── Runs ──────────────────────────────────────────────────────────────────────

@app.get("/api/v1/runs")
def list_runs(limit: int = 50, only_drift: bool = False):
    """List recent runs. Filter to drifting runs only with only_drift=true."""
    runs = history.list_runs(limit=limit, only_drift=only_drift)
    return [asdict(r) for r in runs]


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: int):
    """Full detail for a single run including the complete drift report."""
    run = history.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


@app.get("/api/v1/runs/{run_id}/items")
def get_run_items(
    run_id: int,
    min_severity: str = Query(default="info", pattern="^(info|warn|high|critical)$"),
):
    """Drift items for a specific run, filtered by minimum severity."""
    report = storage.get_report(run_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    threshold = Severity(min_severity)
    items     = report.items_at_or_above(threshold)
    return [item.model_dump() for item in items]


# ── Trend & stats ─────────────────────────────────────────────────────────────

@app.get("/api/v1/trend")
def drift_trend(limit: int = 30):
    """Drift counts over the last N runs — useful for dashboard charting."""
    return history.drift_trend(limit=limit)


@app.get("/api/v1/stats")
def drift_stats():
    """Aggregate statistics: total runs, drift rate, counts by severity."""
    return history.stats()


# ── Latest ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/latest")
def latest_run():
    """Return the most recent drift report, or 204 if no runs exist yet."""
    report = storage.get_latest_report()
    if not report:
        raise HTTPException(status_code=204, detail="No runs recorded yet")
    return report.model_dump(mode="json")


# ── SSE live feed ─────────────────────────────────────────────────────────────

@app.get("/api/v1/stream")
async def stream_drift(last_id: int = 0, poll_seconds: float = 5.0):
    """Server-Sent Events stream — pushes new run summaries as they arrive.

    Connect with:  curl -N http://localhost:8000/api/v1/stream?last_id=0
    """
    async def _generator():
        current = last_id
        while True:
            runs = history.list_runs(limit=1)
            if runs and runs[0].id > current:
                current = runs[0].id
                payload  = _json.dumps(asdict(runs[0]), default=str)
                yield f"data: {payload}\n\n"
            await asyncio.sleep(poll_seconds)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "db": _DB_PATH}
