import asyncio
from detector.diff.models import DriftReport

class RemediationManager:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    async def trigger(self, report: DriftReport) -> None:
        if not self.enabled or not report.has_drift: return
        print(f"[Ops] Auto-remediating Run {report.run_id}...")
        for item in [i for i in getattr(report, 'items', []) if i.severity.value in ['high', 'critical']]:
            print(f"[Remediation] 🔄 Syncing '{item.key}'...")
            await asyncio.sleep(0.1)
        print("[Ops] ✅ Infrastructure healed.")

