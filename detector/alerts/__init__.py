from abc import ABC, abstractmethod
from detector.diff.models import DriftReport, Severity


class BaseAlerter(ABC):
    def __init__(self, min_severity: str = "warn"):
        self.min_severity = Severity(min_severity)

    def _should_alert(self, severity: str) -> bool:
        return Severity(severity) >= self.min_severity

    @abstractmethod
    async def send_alert(self, report: DriftReport) -> None:
        ...
