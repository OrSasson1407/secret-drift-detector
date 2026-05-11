import aiohttp
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport, Severity


_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.WARN:     "🟡",
    Severity.INFO:     "⚪",
}


class SlackAlerter(BaseAlerter):
    def __init__(self, webhook_url: str | None, min_severity: str = "warn"):
        super().__init__(min_severity)
        self.webhook_url = webhook_url

    async def send_alert(self, report: DriftReport) -> None:
        if not self.webhook_url or not report.has_drift:
            return

        items = report.items_at_or_above(self.min_severity)
        if not items:
            return

        sources = ", ".join(report.sources) or "—"
        targets = ", ".join(report.targets) or "—"

        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"🚨 Secret Drift — {len(items)} item(s)"}},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"*Sources:* {sources}"},
                {"type": "mrkdwn", "text": f"*Targets:* {targets}"},
                {"type": "mrkdwn", "text": f"*Checked:* {report.checked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"},
            ]},
        ]

        fields: list[dict] = []
        for item in items:
            icon = _SEV_ICON.get(item.severity, "⚪")
            fields.append({
                "type": "mrkdwn",
                "text": f"{icon} *{item.key}*\n_{item.kind.value}_ — {item.detail}",
            })
            if len(fields) == 10:
                blocks.append({"type": "section", "fields": fields})
                fields = []
        if fields:
            blocks.append({"type": "section", "fields": fields})

        async with aiohttp.ClientSession() as session:
            async with session.post(self.webhook_url, json={"blocks": blocks}) as resp:
                if resp.status >= 400:
                    print(f"[SlackAlerter] HTTP {resp.status}: {await resp.text()}")
