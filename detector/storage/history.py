import json
import os
import hashlib
from dataclasses import dataclass

@dataclass
class RunSummary:
    id: int
    timestamp: str
    expected_count: int
    actual_count: int
    drift_count: int
    has_drift: bool
    max_severity: str | None
    sources: list[str]
    targets: list[str]

def _read_db(path):
    if not os.path.exists(path): return []
    try:
        with open(path, "r") as f: return json.load(f)
    except:
        return []

def _write_db(path, data):
    with open(path, "w") as f: json.dump(data, f, default=str)

def _compute_hash(prev_hash, report_json):
    return hashlib.sha256(f"{prev_hash}{report_json}".encode()).hexdigest()

class History:
    def __init__(self, db_path: str = "drift_history.json"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        if not os.path.exists(self.db_path):
            _write_db(self.db_path, [])

    def list_runs(self, limit: int = 50, only_drift: bool = False):
        data = _read_db(self.db_path)
        runs = []
        for row in reversed(data):
            rep = row.get("report_json", {})
            items = rep.get("items", [])
            has_drift = len(items) > 0
            if only_drift and not has_drift: continue
            runs.append(RunSummary(
                id=row.get("id"),
                timestamp=row.get("timestamp"),
                expected_count=rep.get("expected_count", 0),
                actual_count=rep.get("actual_count", 0),
                drift_count=len(items),
                has_drift=has_drift,
                max_severity=rep.get("max_severity"),
                sources=rep.get("sources", []),
                targets=rep.get("targets", [])
            ))
            if len(runs) >= limit: break
        return runs

    def get_run(self, run_id: int):
        data = _read_db(self.db_path)
        for row in data:
            if row.get("id") == run_id:
                res = dict(row)
                rep = row.get("report_json", {})
                items = rep.get("items", [])
                res.update({
                    "expected_count": rep.get("expected_count", 0),
                    "actual_count": rep.get("actual_count", 0),
                    "has_drift": 1 if len(items) > 0 else 0,
                    "drift_count": len(items),
                    "max_severity": rep.get("max_severity"),
                    "sources": rep.get("sources", []),
                    "targets": rep.get("targets", [])
                })
                return res
        return None

    def drift_trend(self, limit: int = 30):
        data = _read_db(self.db_path)
        trend = []
        for row in list(reversed(data))[:limit]:
            rep = row.get("report_json", {})
            items = rep.get("items", [])
            trend.append({
                "timestamp": row.get("timestamp"),
                "drift_count": len(items),
                "has_drift": 1 if len(items) > 0 else 0,
                "max_severity": rep.get("max_severity")
            })
        return list(reversed(trend))

    def stats(self):
        data = _read_db(self.db_path)
        total = len(data)
        drifts = sum(1 for row in data if len(row.get("report_json", {}).get("items", [])) > 0)
        return {
            "total_runs": total,
            "drift_rate": (drifts / total) if total > 0 else 0.0,
            "drifting_runs": drifts
        }
