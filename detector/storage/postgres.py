import json
import psycopg2
from psycopg2.extras import RealDictCursor
from detector.diff.models import DriftReport

class PostgresStorage:
    def __init__(self, connection_string: str):
        self.conn_str = connection_string
        self._init_db()

    def _init_db(self):
        with psycopg2.connect(self.conn_str) as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS drift_runs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ DEFAULT NOW(),
                        report_json JSONB NOT NULL,
                        prev_hash TEXT
                    )
                ''')
            conn.commit()

    def save_report(self, report: DriftReport):
        with psycopg2.connect(self.conn_str) as conn:
            with conn.cursor() as cur:
                report_json = report.model_dump_json()
                cur.execute(
                    "INSERT INTO drift_runs (report_json) VALUES (%s) RETURNING id",
                    (report_json,)
                )
                run_id = cur.fetchone()[0]
            conn.commit()
        return run_id
