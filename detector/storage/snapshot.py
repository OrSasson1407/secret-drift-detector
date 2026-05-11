import sqlite3
import json
from datetime import datetime, timezone
from detector.diff.models import DriftReport

class Storage:
    def __init__(self, db_path: str = 'drift_history.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    expected_count INTEGER,
                    actual_count INTEGER,
                    drift_count INTEGER,
                    has_drift BOOLEAN,
                    report_json TEXT
                )
            ''')

    def save_report(self, report: DriftReport):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                '''INSERT INTO runs 
                   (timestamp, expected_count, actual_count, drift_count, has_drift, report_json) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    datetime.now(timezone.utc).isoformat(), 
                    report.expected_count, 
                    report.actual_count, 
                    len(report.items), 
                    report.has_drift, 
                    report.model_dump_json()
                )
            )
