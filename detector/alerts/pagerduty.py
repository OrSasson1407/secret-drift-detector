import aiohttp
import os
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport, Severity

class PagerDutyAlerter(BaseAlerter):
    def __init__(self, integration_key: str, min_severity: str = 'critical'):
        super().__init__(Severity(min_severity))
        if integration_key.startswith('env:'):
            self.integration_key = os.environ.get(integration_key[4:])
        else:
            self.integration_key = integration_key

    async def send_alert(self, report: DriftReport, source_name: str, target_name: str):
        if not self.integration_key or not report.has_drift:
            return

        actionable_items = [i for i in report.items if self._should_alert(i.severity.value)]
        if not actionable_items:
            return

        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"Secret Drift Detected in {target_name}",
                "severity": "critical",
                "source": target_name,
                "custom_details": {
                    "source_configs": source_name,
                    "drift_items": [i.model_dump() for i in actionable_items]
                }
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post('https://events.pagerduty.com/v2/enqueue', json=payload) as resp:
                if resp.status >= 400:
                    print(f"Failed to send PD alert: {await resp.text()}")
