import aiohttp
import os
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport, Severity

class SlackAlerter(BaseAlerter):
    def __init__(self, webhook_url: str, min_severity: str = 'warn'):
        super().__init__(Severity(min_severity))
        # Handle 'env:VAR_NAME' syntax from config
        if webhook_url.startswith('env:'):
            self.webhook_url = os.environ.get(webhook_url[4:])
        else:
            self.webhook_url = webhook_url

    async def send_alert(self, report: DriftReport, source_name: str, target_name: str):
        if not self.webhook_url or not report.has_drift:
            return

        # Filter items by severity
        actionable_items = [i for i in report.items if self._should_alert(i.severity.value)]
        if not actionable_items:
            return

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Secret Drift Detected: {len(actionable_items)} items"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Source:* {source_name}"},
                    {"type": "mrkdwn", "text": f"*Target:* {target_name}"}
                ]
            }
        ]

        fields = []
        for item in actionable_items:
            icon = "🔴" if item.severity.value in ['critical', 'high'] else "🟡"
            fields.append({
                "type": "mrkdwn",
                "text": f"{icon} *{item.key}*\n_{item.kind.value}_ - {item.detail}"
            })
            
            # Slack limits fields to 10 per section
            if len(fields) == 10:
                blocks.append({"type": "section", "fields": fields})
                fields = []

        if fields:
            blocks.append({"type": "section", "fields": fields})

        payload = {"blocks": blocks}

        async with aiohttp.ClientSession() as session:
            async with session.post(self.webhook_url, json=payload) as resp:
                if resp.status >= 400:
                    print(f"Failed to send Slack alert: {await resp.text()}")
