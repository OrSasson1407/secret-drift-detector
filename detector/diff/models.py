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

    def __le__(self, other: "Severity") -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class DriftItem(BaseModel):
    key:               str
    kind:              DriftKind
    severity:          Severity = Severity.INFO
    detail:            str = ""
    remediation_hint:  str = ""

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL


class DriftReport(BaseModel):
    run_id:         int | None = None          # filled in by Storage after persist
    items:          list[DriftItem] = Field(default_factory=list)
    expected_count: int = 0
    actual_count:   int = 0
    checked_at:     datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sources:        list[str] = Field(default_factory=list)
    targets:        list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------ queries
    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.items:
            return None
        return max(self.items, key=lambda i: i.severity.rank).severity

    def items_at_or_above(self, min_severity: Severity) -> list["DriftItem"]:
        return [i for i in self.items if i.severity >= min_severity]

    def by_kind(self, kind: DriftKind) -> list["DriftItem"]:
        return [i for i in self.items if i.kind == kind]

    # ------------------------------------------------------------------ summary
    def summary(self) -> dict:
        """Compact dict suitable for logging / alert headers."""
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.severity.value] = counts.get(item.severity.value, 0) + 1
        return {
            "run_id":         self.run_id,
            "checked_at":     self.checked_at.isoformat(),
            "has_drift":      self.has_drift,
            "total_items":    len(self.items),
            "by_severity":    counts,
            "max_severity":   self.max_severity.value if self.max_severity else None,
            "expected_count": self.expected_count,
            "actual_count":   self.actual_count,
        }
