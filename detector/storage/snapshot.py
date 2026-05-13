import hashlib
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
    report_json    TEXT    NOT NULL,
    prev_hash      TEXT,
    report_hash    TEXT
)
"""

_EXTRA_COLS = [
    ("max_severity", "TEXT"),
    ("sources",      "TEXT"),
    ("targets",      "TEXT"),
    ("prev_hash",    "TEXT"),
    ("report_hash",  "TEXT"),
]


from detector.storage.history import _compute_hash


class Storage:
    def __init__(self, db_path: str = "drift_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_DDL)
            for col, typedef in _EXTRA_COLS:
                try:
                    conn.execute(f"ALTER TABLE runs ADD COLUMN {col} {typedef}")
                except sqlite3.OperationalError:
                    pass

    # ------------------------------------------------------------------ write

    def save_report(self, report: DriftReport) -> int:
        """Persist a DriftReport with audit hash chain. Returns the new run ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get the hash of the previous run (chain link)
            row = conn.execute(
                "SELECT report_hash FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["report_hash"] if row else None

            report_json  = report.model_dump_json()
            report_hash  = _compute_hash(prev_hash, report_json)

            cur = conn.execute(
                """INSERT INTO runs
                   (timestamp, expected_count, actual_count, drift_count,
                    has_drift, max_severity, sources, targets, report_json,
                    prev_hash, report_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report.checked_at.isoformat(),
                    report.expected_count,
                    report.actual_count,
                    len(report.items),
                    int(report.has_drift),
                    report.max_severity.value if report.max_severity else None,
                    json.dumps(report.sources),
                    json.dumps(report.targets),
                    report_json,
                    prev_hash,
                    report_hash,
                ),
            )
            return cur.lastrowid

    # ------------------------------------------------------------------ read

    def get_latest_report(self) -> DriftReport | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT report_json FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return DriftReport.model_validate_json(row["report_json"])

    def get_report(self, run_id: int) -> DriftReport | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT report_json FROM runs WHERE id=?", (run_id,)
            ).fetchone()
        if not row:
            return None
        return DriftReport.model_validate_json(row["report_json"])

    # ------------------------------------------------------------------ prune

    def delete_old_runs(self, keep: int = 500) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """DELETE FROM runs WHERE id NOT IN (
                       SELECT id FROM runs ORDER BY id DESC LIMIT ?
                   )""",
                (keep,),
            )
            return cur.rowcount

