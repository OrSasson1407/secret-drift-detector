from abc import ABC, abstractmethod
from detector.diff.models import DriftReport, Severity

class BaseAlerter(ABC):
    def __init__(self, min_severity: Severity = Severity.WARN):
        self.min_severity = min_severity

    def _should_alert(self, item_severity: str) -> bool:
        # Simple severity hierarchy mapping
        hierarchy = {'info': 0, 'warn': 1, 'high': 2, 'critical': 3}
        item_level = hierarchy.get(item_severity.lower(), 0)
        min_level = hierarchy.get(self.min_severity.value.lower(), 1)
        return item_level >= min_level

    @abstractmethod
    async def send_alert(self, report: DriftReport, source_name: str, target_name: str):
        pass
