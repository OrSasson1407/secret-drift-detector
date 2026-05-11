import aiohttp
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport

_PD_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyAlerter(BaseAlerter):
    def __init__(self, integration_key: str | None, min_severity: str = "critical"):
        super().__init__(min_severity)
        self.integration_key = integration_key

    async def send_alert(self, report: DriftReport) -> None:
        if not self.integration_key or not report.has_drift:
            return

        items = report.items_at_or_above(self.min_severity)
        if not items:
            return

        payload = {
            "routing_key":  self.integration_key,
            "event_action": "trigger",
            "payload": {
                "summary":  f"Secret Drift: {len(items)} item(s) in {', '.join(report.targets) or 'unknown'}",
                "severity": "critical",
                "source":   ", ".join(report.targets) or "secret-drift-detector",
                "timestamp": report.checked_at.isoformat(),
                "custom_details": {
                    "sources":     report.sources,
                    "targets":     report.targets,
                    "drift_items": [i.model_dump() for i in items],
                },
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(_PD_URL, json=payload) as resp:
                if resp.status >= 400:
                    print(f"[PagerDutyAlerter] HTTP {resp.status}: {await resp.text()}")
