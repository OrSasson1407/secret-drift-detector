from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class DriftKind(str, Enum):
    MISSING_IN_RUNTIME = "missing"   # in expected, absent from live env
    EXTRA_IN_RUNTIME   = "extra"     # in live env, absent from expected
    VALUE_CHANGED      = "changed"   # key present both sides, hash differs
    STALE_SECRET       = "stale"     # rotation deadline exceeded


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    WARN     = "warn"
    INFO     = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "warn": 2, "info": 1}[self.value]

    def __ge__(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank


class DriftItem(BaseModel):
    key:      str
    kind:     DriftKind
    severity: Severity = Severity.INFO
    detail:   str = ""


class DriftReport(BaseModel):
    items:          list[DriftItem] = Field(default_factory=list)
    expected_count: int = 0
    actual_count:   int = 0
    checked_at:     datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources:        list[str] = Field(default_factory=list)
    targets:        list[str] = Field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.items:
            return None
        return max(self.items, key=lambda i: i.severity.rank).severity

    def items_at_or_above(self, min_severity: Severity) -> list[DriftItem]:
        return [i for i in self.items if i.severity >= min_severity]
