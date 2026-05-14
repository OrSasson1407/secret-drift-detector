import aiohttp
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport

class JiraAlerter(BaseAlerter):
    def __init__(self, url: str, username: str, token: str, project_key: str, min_severity: str = "warn"):
        self.url = url
        self.username = username
        self.token = token
        self.project_key = project_key
        self.min_severity = min_severity

    

    

    async def send_alert(self, report: DriftReport) -> None:
        if not self.url or not report.has_drift:
            return

        items = self._filter_items(report)
        if not items:
            return

        description = f"Drift Run ID: {report.run_id}\nChecked at: {report.checked_at}\n\n*Drifted Secrets:*\n"
        for item in items:
            description += f"- {item.key} ({item.kind.value}): {item.detail}\n"

        # Formatted for Agile workflow integration
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"Secret Drift Alert - {len(items)} issues detected",
                "description": description,
                "issuetype": {"name": "Task"} 
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.url, json=payload) as resp:
                if resp.status >= 400:
                    print(f"[JiraAlerter] Failed to create task: {await resp.text()}")

