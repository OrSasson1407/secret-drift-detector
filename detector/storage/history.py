import hashlib
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


def _compute_hash(prev_hash: str | None, report_json: str) -> str:
    data = (prev_hash or "") + report_json
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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
        return [self._row_to_summary(r) for r in rows]

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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,drift_count,has_drift,max_severity "
                "FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # ------------------------------------------------------------------ stats

    def stats(self) -> dict[str, Any]:
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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,expected_count,actual_count,"
                "drift_count,has_drift,max_severity,sources,targets "
                "FROM runs WHERE has_drift=1 AND report_json LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f'%"{key_name}"%', limit),
            ).fetchall()
        return [self._row_to_summary(r) for r in rows]

    # ------------------------------------------------------------------ prune

    def delete_before(self, before_iso: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM runs WHERE timestamp < ?", (before_iso,)
            )
            return cur.rowcount

    # ------------------------------------------------------------------ verify chain

    def verify_chain(self, limit: int = 100) -> list[dict]:
        """
        Walk the audit hash chain for the most recent *limit* runs (oldest first)
        and return a list of dicts with chain verification results.

        Each dict contains:
          id, timestamp, stored_hash, expected_hash, prev_hash, chain_ok
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, timestamp, report_json, prev_hash, report_hash "
                "FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        # Reverse to oldest-first for sequential verification
        rows = list(reversed(rows))

        results: list[dict] = []
        running_prev: str | None = None

        for i, row in enumerate(rows):
            stored_hash   = row["report_hash"]
            stored_prev   = row["prev_hash"]
            report_json   = row["report_json"]
            expected_hash = _compute_hash(running_prev, report_json)

            # Chain is OK if:
            #   1. The stored prev_hash matches what we tracked
            #   2. The stored report_hash matches our recomputed hash
            prev_ok  = (stored_prev == running_prev)
            hash_ok  = (stored_hash == expected_hash)
            chain_ok = prev_ok and hash_ok

            results.append({
                "id":            row["id"],
                "timestamp":     row["timestamp"],
                "stored_hash":   stored_hash,
                "expected_hash": expected_hash,
                "prev_hash":     stored_prev,
                "chain_ok":      chain_ok,
            })

            # Advance the running hash (use stored so gaps propagate correctly)
            running_prev = stored_hash

        return results

