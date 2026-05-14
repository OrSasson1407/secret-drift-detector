import aiohttp
from aiohttp import ClientTimeout
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport


class WebhookAlerter(BaseAlerter):
    """Generic HTTP POST alerter — sends the full DriftReport as JSON."""

    def __init__(self, url: str | None, min_severity: str = "warn",
                 headers: dict[str, str] | None = None):
        super().__init__(min_severity)
        self.url     = url
        self.headers = headers or {}

    async def send_alert(self, report: DriftReport) -> None:
        if not self.url or not report.has_drift:
            return

        if not report.items_at_or_above(self.min_severity):
            return

        payload = report.model_dump(mode="json")

        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.post(self.url, json=payload) as resp:
                if resp.status >= 400:
                    print(f"[WebhookAlerter] HTTP {resp.status}: {await resp.text()}")
