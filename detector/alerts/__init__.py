from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from detector.diff.models import DriftReport, DriftItem, Severity


@dataclass
class AlertResult:
    """Outcome of a single alerter dispatch."""
    alerter:  str
    success:  bool
    error:    str | None = None
    items_sent: int      = 0


class BaseAlerter(ABC):
    def __init__(self, min_severity: str = "warn"):
        self.min_severity = Severity(min_severity)

    def _filter_items(self, report: DriftReport) -> list[DriftItem]:
        """Return only the items that meet this alerter's minimum severity."""
        return report.items_at_or_above(self.min_severity)

    def _should_alert(self, severity: str) -> bool:
        return Severity(severity) >= self.min_severity

    @abstractmethod
    async def send_alert(self, report: DriftReport) -> None:
        ...

    async def send_with_result(self, report: DriftReport) -> AlertResult:
        """Wrapper that captures success/failure into an AlertResult."""
        name = self.__class__.__name__
        items = self._filter_items(report)
        try:
            await self.send_alert(report)
            return AlertResult(alerter=name, success=True, items_sent=len(items))
        except Exception as exc:
            return AlertResult(alerter=name, success=False, error=str(exc))
