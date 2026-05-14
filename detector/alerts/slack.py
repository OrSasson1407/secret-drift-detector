import asyncio
import aiohttp
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport, Severity

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.WARN:     "🟡",
    Severity.INFO:     "⚪",
}

_MAX_RETRIES  = 2
_RETRY_DELAY  = 5.0   # seconds to wait after a 429


class SlackAlerter(BaseAlerter):
    def __init__(
        self,
        webhook_url:  str | None,
        min_severity: str = "warn",
        mention:      str | None = None,
    ):
        super().__init__(min_severity)
        self.webhook_url = webhook_url
        self.mention     = mention   # e.g. "<!channel>" or "<@U12345>"

    async def send_alert(self, report: DriftReport) -> None:
        if not self.webhook_url or not report.has_drift:
            return

        items = self._filter_items(report)
        if not items:
            return

        sources = ", ".join(report.sources) or "—"
        targets = ", ".join(report.targets) or "—"
        ts      = report.checked_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        header_text = f"🚨 Secret Drift — {len(items)} item(s)"
        if self.mention:
            header_text = f"{self.mention} {header_text}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Sources:* {sources}"},
                    {"type": "mrkdwn", "text": f"*Targets:* {targets}"},
                    {"type": "mrkdwn", "text": f"*Checked:* {ts}"},
                ],
            },
            {"type": "divider"},
        ]

        # Group items into section blocks (Slack max 10 fields per section)
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

        if report.run_id:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Run ID: {report.run_id}"}],
            })
            
            # --- NEW: Interactive Actions for Slack ---
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Acknowledge"
                        },
                        "style": "primary",
                        "action_id": "ack_drift",
                        "value": str(report.run_id)
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "💤 Snooze (1h)"
                        },
                        "action_id": "snooze_drift",
                        "value": str(report.run_id)
                    }
                ]
            })

        await self._post_with_retry({"blocks": blocks})

    async def _post_with_retry(self, payload: dict) -> None:
        async with aiohttp.ClientSession() as session:
            for attempt in range(3):
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status == 200:
                        return
                    if resp.status == 429 and attempt < _MAX_RETRIES:
                        retry_after = float(resp.headers.get("Retry-After", _RETRY_DELAY))
                        await asyncio.sleep(retry_after)
                        continue
                    body = await resp.text()
                    print(f"[SlackAlerter] HTTP {resp.status} (attempt {attempt}): {body}")

