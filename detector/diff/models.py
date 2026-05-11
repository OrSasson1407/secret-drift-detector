from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class DriftKind(str, Enum):
    MISSING_IN_RUNTIME = "missing"
    EXTRA_IN_RUNTIME   = "extra"
    VALUE_CHANGED      = "changed"
    STALE_SECRET       = "stale"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    WARN     = "warn"
    INFO     = "info"


_SEV_ORDER = {"critical": 3, "high": 2, "warn": 1, "info": 0}


def sev_gte(a: Severity, b: Severity) -> bool:
    return _SEV_ORDER[a.value] >= _SEV_ORDER[b.value]


class DriftItem(BaseModel):
    key:      str
    kind:     DriftKind
    severity: Severity = Severity.INFO
    detail:   str = ""


class DriftReport(BaseModel):
    items:          List[DriftItem] = Field(default_factory=list)
    expected_count: int = 0
    actual_count:   int = 0
    checked_at:     datetime = Field(default_factory=datetime.utcnow)
    source_labels:  List[str] = Field(default_factory=list)
    target_label:   str = ""

    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.items:
            return None
        return max(self.items, key=lambda i: _SEV_ORDER[i.severity.value]).severity

    def items_at_or_above(self, threshold: Severity) -> List[DriftItem]:
        return [i for i in self.items if _SEV_ORDER[i.severity.value] >= _SEV_ORDER[threshold.value]]
