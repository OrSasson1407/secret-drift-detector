from rich.console import Console
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport

console = Console()


class StdoutAlerter(BaseAlerter):
    async def send_alert(self, report: DriftReport) -> None:
        items = report.items_at_or_above(self.min_severity)
        for item in items:
            console.print(f"[red]DRIFT[/red] {item.key} | {item.kind.value} | {item.severity.value}")
