import json
import os
from datetime import datetime, timezone
from detector.diff.models import DriftReport
from detector.storage.history import _read_db, _write_db, _compute_hash

class Storage:
    def __init__(self, db_path: str = "drift_history.json"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        if not os.path.exists(self.db_path):
            _write_db(self.db_path, [])

    def save_report(self, report: DriftReport) -> int:
        data = _read_db(self.db_path)
        new_id = max([r.get("id", 0) for r in data], default=0) + 1
        
        report_dict = report.model_dump()
        report_json_str = json.dumps(report_dict, default=str)
        
        prev_hash = data[-1].get("hash") if data else "0" * 64
        current_hash = _compute_hash(prev_hash, report_json_str)
        
        row = {
            "id": new_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "report_json": report_dict,
            "prev_hash": prev_hash,
            "hash": current_hash
        }
        data.append(row)
        _write_db(self.db_path, data)
        return new_id

    def delete_old_runs(self, keep: int) -> int:
        data = self._load()
        if len(data) <= keep:
            return 0
        
        # Sort by ID to ensure we delete the oldest
        data.sort(key=lambda x: x.get("id", 0))
        to_delete = len(data) - keep
        self._save(data[to_delete:])
        return to_delete
