import json
import sqlite3
from datetime import datetime, timezone
from detector.diff.models import DriftReport


_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    expected_count INTEGER NOT NULL DEFAULT 0,
    actual_count   INTEGER NOT NULL DEFAULT 0,
    drift_count    INTEGER NOT NULL DEFAULT 0,
    has_drift      INTEGER NOT NULL DEFAULT 0,
    max_severity   TEXT,
    sources        TEXT,
    targets        TEXT,
    report_json    TEXT    NOT NULL
)
"""


class Storage:
    def __init__(self, db_path: str = "drift_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_DDL)
            # Add columns introduced in this upgrade (idempotent)
            for col, typedef in [("max_severity","TEXT"), ("sources","TEXT"), ("targets","TEXT")]:
                try:
                    conn.execute(f"ALTER TABLE runs ADD COLUMN {col} {typedef}")
                except sqlite3.OperationalError:
                    pass  # column already exists

    def save_report(self, report: DriftReport) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """INSERT INTO runs
                   (timestamp, expected_count, actual_count, drift_count,
                    has_drift, max_severity, sources, targets, report_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    report.checked_at.isoformat(),
                    report.expected_count,
                    report.actual_count,
                    len(report.items),
                    int(report.has_drift),
                    report.max_severity.value if report.max_severity else None,
                    json.dumps(report.sources),
                    json.dumps(report.targets),
                    report.model_dump_json(),
                ),
            )
            return cur.lastrowid
