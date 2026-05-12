import os
class PostgresStorage:
    def __init__(self, uri: str = None):
        self.uri = uri or os.environ.get("DRIFT_DB_URI", "")
    async def connect(self): print(f"[DB] Connected to {self.uri}")
    async def list_runs(self, limit=50, only_drift=False): return []
    async def get_report(self, rid): return None
    async def drift_trend(self, lim=30): return []
    async def stats(self): return {"total_runs": 0, "drift_rate": 0.0}
    async def save_report(self, rid, js): print(f"[DB] Saved {rid}")
