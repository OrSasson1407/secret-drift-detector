import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------ lists

    def list_runs(self, limit: int = 50, only_drift: bool = False) -> list[RunSummary]:
        query = (
            "SELECT id,timestamp,expected_count,actual_count,"
            "drift_count,has_drift,max_severity,sources,targets FROM runs"
        )
        if only_drift:
            query += " WHERE has_drift=1"
        query += " ORDER BY id DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(query, (limit,)).fetchall()
        return [_row_to_summary(r) for r in rows]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["report_json"] = json.loads(d["report_json"])
        d["sources"]     = json.loads(d.get("sources") or "[]")
        d["targets"]     = json.loads(d.get("targets") or "[]")
        return d

    # ------------------------------------------------------------------ trend

    def drift_trend(self, limit: int = 30) -> list[dict]:
        """Last N runs summarised for trend charting — oldest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,drift_count,has_drift,max_severity "
                "FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # ------------------------------------------------------------------ stats

    def stats(self) -> dict[str, Any]:
        """Aggregate statistics across all recorded runs."""
        with self._connect() as conn:
            totals = conn.execute(
                "SELECT COUNT(*) as total, SUM(has_drift) as drifted, "
                "SUM(drift_count) as total_items FROM runs"
            ).fetchone()

            sev_rows = conn.execute(
                "SELECT max_severity, COUNT(*) as cnt FROM runs "
                "WHERE has_drift=1 AND max_severity IS NOT NULL "
                "GROUP BY max_severity"
            ).fetchall()

        total   = totals["total"] or 0
        drifted = totals["drifted"] or 0
        drift_rate = round(drifted / total * 100, 1) if total else 0.0

        return {
            "total_runs":        total,
            "drifted_runs":      drifted,
            "clean_runs":        total - drifted,
            "drift_rate_pct":    drift_rate,
            "total_drift_items": totals["total_items"] or 0,
            "by_max_severity":   {r["max_severity"]: r["cnt"] for r in sev_rows},
        }

    # ------------------------------------------------------------------ search

    def search_by_key(self, key_name: str, limit: int = 50) -> list[RunSummary]:
        """Return runs where *key_name* appears in the drift report."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,expected_count,actual_count,"
                "drift_count,has_drift,max_severity,sources,targets "
                "FROM runs WHERE has_drift=1 AND report_json LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f'%"{key_name}"%', limit),
            ).fetchall()
        return [_row_to_summary(r) for r in rows]

    # ------------------------------------------------------------------ prune

    def delete_before(self, before_iso: str) -> int:
        """Delete all runs with a timestamp earlier than *before_iso*.

        Returns the number of rows deleted.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM runs WHERE timestamp < ?", (before_iso,)
            )
            return cur.rowcount


# ------------------------------------------------------------------ helpers

def _row_to_summary(r: sqlite3.Row) -> RunSummary:
    return RunSummary(
        id=r["id"],
        timestamp=r["timestamp"],
        expected_count=r["expected_count"],
        actual_count=r["actual_count"],
        drift_count=r["drift_count"],
        has_drift=bool(r["has_drift"]),
        max_severity=r["max_severity"],
        sources=json.loads(r["sources"] or "[]"),
        targets=json.loads(r["targets"] or "[]"),
    )
