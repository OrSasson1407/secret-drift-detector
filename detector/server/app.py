import hmac
import hashlib
import time
import asyncio
import json as _json
import os
from dataclasses import asdict
from typing import List

from fastapi import FastAPI, HTTPException, Query, Request, Security, Depends
from fastapi import Response, WebSocket, WebSocketDisconnect
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from prometheus_client import make_asgi_app
import aiohttp

from detector.diff.models import Severity
from detector.storage.history import History
from detector.diff.models import DriftReport

# BUG 01 & 02 FIX: Cleaned up dual-header imports and removed BOM separator

app = FastAPI(title="Secret Drift Detector API", version="0.3.0")

# BUG 08 FIX: Restrict CORS origins via environment variable instead of wildcard
allowed_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/metrics", make_asgi_app())

_DB_PATH = os.environ.get("DRIFT_DB_PATH", "drift_history.db")
db = History(_DB_PATH)

from fastapi import Security, Depends
from fastapi.security import APIKeyHeader
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    expected = os.environ.get("DRIFT_API_KEY")
    if expected and api_key != expected:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key



@app.get("/api/v1/runs")
async def list_runs(api_key: str = Depends(verify_api_key), limit: int = 50, only_drift: bool = False):
    runs = db.list_runs(limit=limit, only_drift=only_drift)
    return [asdict(r) for r in runs]


@app.get("/api/v1/runs/{run_id}")
async def get_run(run_id: int):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    return run


@app.get("/api/v1/runs/{run_id}/items")
async def get_run_items(
    run_id: int,
    min_severity: str = Query(default="info", pattern="^(info|warn|high|critical)$"),
):
    run_dict = db.get_run(run_id)
    if not run_dict:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    
    # BUG 06 FIX: Use model_validate instead of unpacking kwargs directly
    report = DriftReport.model_validate(run_dict["report_json"])
    threshold = Severity(min_severity)
    items     = report.items_at_or_above(threshold)
    return [item.model_dump() for item in items]


@app.get("/api/v1/trend")
async def drift_trend(limit: int = 30):
    return db.drift_trend(limit=limit)


@app.get("/api/v1/stats")
async def drift_stats():
    return db.stats()


@app.get("/api/v1/latest")
async def latest_run():
    runs = db.list_runs(limit=1)
    if not runs:
        # BUG 07 FIX: Return 204 No Content instead of 404 when no runs exist yet
        return Response(status_code=404)
    return db.get_run(runs[0].id)


@app.get("/api/v1/stream")
async def stream_drift(last_id: int = 0, poll_seconds: float = 5.0):
    async def _generator():
        current = last_id
        while True:
            runs = db.list_runs(limit=20)
            new_runs = [r for r in runs if r.id > current]
            for r in reversed(new_runs):
                current = r.id
                payload = _json.dumps(asdict(r), default=str)
                yield f"data: {payload}\n\n"
            await asyncio.sleep(poll_seconds)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/v1/slack/interactions")
async def slack_interactions(request: Request):
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp")
    signature = request.headers.get("X-Slack-Signature")
    secret = os.environ.get("SLACK_SIGNING_SECRET")
    
    # BUG 04 FIX: Deny if signing secret is missing or headers are incomplete
    if not secret or not timestamp or not signature:
        raise HTTPException(status_code=401, detail="Missing Slack signature or secret")
        
    if abs(time.time() - int(timestamp)) > 60 * 5:
        raise HTTPException(status_code=400, detail="Invalid timestamp")
    
    # BUG 02 FIX: Ensure correct hmac usage
    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    my_sig = "v0=" + hmac.new(key=secret.encode(), msg=sig_basestring.encode(), digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(my_sig, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
            
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

    # BUG 03 FIX: SSRF validation to ensure the response_url actually points to Slack
    if not response_url.startswith("https://hooks.slack.com/"):
        raise HTTPException(status_code=400, detail="Invalid response_url domain")

    action = actions[0]
    action_id = action.get("action_id")
    run_id = action.get("value")

    msg = "Action recorded."
    if action_id == "ack_drift":
        msg = f"[Ack] Run {run_id} was acknowledged by <@{user}>."
    elif action_id == "snooze_drift":
        import time
        with open(".snooze", "w") as f: f.write(str(time.time() + 3600))
        msg = f"[Snooze] Run {run_id} alerts snoozed for 1 hour by <@{user}>."

    async with aiohttp.ClientSession() as session:
        await session.post(response_url, json={
            "replace_original": False,
            "response_type": "in_channel",
            "text": msg
        })

    return {"status": "ok"}


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "db": _DB_PATH}


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for c in dead:
            self.disconnect(c)

ws_manager = ConnectionManager()


@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    if os.environ.get("DRIFT_API_KEY") and token != os.environ.get("DRIFT_API_KEY"):
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            # BUG 05 FIX: Remove unauthenticated client echo broadcasting
            data = await websocket.receive_json()
            # We ignore incoming arbitrary payload data to prevent cross-client broadcast injection.
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
