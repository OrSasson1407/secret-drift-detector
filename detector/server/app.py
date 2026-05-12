import asyncio
import json as _json
import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from prometheus_client import make_asgi_app
import aiohttp

from detector.diff.models import Severity
from detector.storage.postgres import PostgresStorage


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
db = PostgresStorage()



# ── Runs ──────────────────────────────────────────────────────────────────────

@app.get("/api/v1/runs")
async def list_runs(limit: int = 50, only_drift: bool = False):
    """List recent runs. Filter to drifting runs only with only_drift=true."""
    runs = await db.list_runs(limit=limit, only_drift=only_drift)
    return [asdict(r) for r in runs]


@app.get("/api/v1/runs/{run_id}")
async def get_run(run_id: int):
    """Full detail for a single run including the complete drift report."""
    run = await db.get_report(run_id)
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
async def drift_trend(limit: int = 30):
    """Drift counts over the last N runs — useful for dashboard charting."""
    return await db.drift_trend(limit=limit)


@app.get("/api/v1/stats")
async def drift_stats():
    """Aggregate statistics: total runs, drift rate, counts by severity."""
    return await db.stats()


# ── Latest ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/latest")
async def latest_run():
    """Return the most recent drift report, or 204 if no runs exist yet."""
    report = await db.get_latest_report()
    if not report:
        raise HTTPException(status_code=204, detail="No runs recorded yet")
    return report.model_dump(mode="json")


# ── SSE live feed ─────────────────────────────────────────────────────────────

@app.get("/api/v1/stream")
async def stream_drift(last_id: int = 0, poll_seconds: float = 5.0):
    """Server-Sent Events stream — pushes new run summaries as they arrive."""
    async def _generator():
        current = last_id
        while True:
            runs = await db.list_runs(limit=1)
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

# ── Slack Interactions ────────────────────────────────────────────────────────

@app.post("/api/v1/slack/interactions")
async def slack_interactions(request: Request):
    """Handle Interactive Button Clicks from Slack"""
    form = await request.form()
    payload_str = form.get("payload")
    
    if not payload_str:
        raise HTTPException(status_code=400, detail="No payload provided")
    
    payload = _json.loads(payload_str)
    actions = payload.get("actions", [])
    response_url = payload.get("response_url")
    user = payload.get("user", {}).get("id", "Unknown")

    if not actions or not response_url:
        return {"status": "ignored"}

    action = actions[0]
    action_id = action.get("action_id")
    run_id = action.get("value")

    msg = "Action recorded."
    if action_id == "ack_drift":
        msg = f"✅ Run {run_id} was acknowledged by <@{user}>."
        # In a full setup, here you would mark the drift run as 'Acknowledge' in the DB history
    elif action_id == "snooze_drift":
        msg = f"💤 Run {run_id} alerts snoozed for 1 hour by <@{user}>."
        # In a full setup, you'd add this to a Redis key or DB row to bypass alerts

    # Post an update back to Slack so the rest of the team sees the action
    async with aiohttp.ClientSession() as session:
        await session.post(response_url, json={
            "replace_original": False,
            "response_type": "in_channel",
            "text": msg
        })

    return {"status": "ok"}

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "db": _DB_PATH}

# ── Real-Time WebSockets (Bidirectional) ──────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect
from typing import List

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

ws_manager = ConnectionManager()

@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Broadcast state changes (e.g. Snooze/Ack) so all connected React clients sync instantly
            await ws_manager.broadcast(data)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

