from enum import Enum
from pydantic import BaseModel

class DriftKind(str, Enum):
    MISSING_IN_RUNTIME = 'missing'
    EXTRA_IN_RUNTIME = 'extra'
    VALUE_CHANGED = 'changed'
    STALE_SECRET = 'stale'

class Severity(str, Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    WARN = 'warn'
    INFO = 'info'

class DriftItem(BaseModel):
    key: str
    kind: DriftKind
    severity: Severity = Severity.INFO
    detail: str = ""

class DriftReport(BaseModel):
    items: list[DriftItem]
    expected_count: int
    actual_count: int

    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0
