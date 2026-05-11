import json
import sqlite3
from dataclasses import dataclass
from typing import Any


@dataclass
class RunSummary:
    id:             int
    timestamp:      str
    expected_count: int
    actual_count:   int
    drift_count:    int
    has_drift:      bool
    max_severity:   str | None
    sources:        list[str]
    targets:        list[str]


class History:
    def __init__(self, db_path: str = "drift_history.db"):
        self.db_path = db_path

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def list_runs(self, limit: int = 50, only_drift: bool = False) -> list[RunSummary]:
        query = "SELECT id,timestamp,expected_count,actual_count,drift_count,has_drift,max_severity,sources,targets FROM runs"
        if only_drift:
            query += " WHERE has_drift=1"
        query += " ORDER BY id DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, (limit,)).fetchall()
        return [
            RunSummary(
                id=r["id"], timestamp=r["timestamp"],
                expected_count=r["expected_count"], actual_count=r["actual_count"],
                drift_count=r["drift_count"], has_drift=bool(r["has_drift"]),
                max_severity=r["max_severity"],
                sources=json.loads(r["sources"] or "[]"),
                targets=json.loads(r["targets"] or "[]"),
            )
            for r in rows
        ]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["report_json"]  = json.loads(d["report_json"])
        d["sources"]      = json.loads(d.get("sources") or "[]")
        d["targets"]      = json.loads(d.get("targets") or "[]")
        return d

    def drift_trend(self, limit: int = 30) -> list[dict]:
        """Return the last N runs summarised for trend charting."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,drift_count,has_drift,max_severity FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]
