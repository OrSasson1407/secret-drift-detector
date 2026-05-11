from __future__ import annotations

import hashlib
from typing import Dict

from .models import DriftItem, DriftKind, DriftReport
from .scorer import score_report_items


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def compute_drift(
    expected: Dict[str, str],
    actual: Dict[str, str],
    source_labels: list[str] | None = None,
    target_label: str = "",
) -> DriftReport:
    items: list[DriftItem] = []

    expected_keys = set(expected.keys())
    actual_keys   = set(actual.keys())

    for key in sorted(expected_keys - actual_keys):
        items.append(DriftItem(key=key, kind=DriftKind.MISSING_IN_RUNTIME))

    for key in sorted(actual_keys - expected_keys):
        items.append(DriftItem(key=key, kind=DriftKind.EXTRA_IN_RUNTIME))

    for key in sorted(expected_keys & actual_keys):
        if _hash(expected[key]) != _hash(actual[key]):
            items.append(DriftItem(key=key, kind=DriftKind.VALUE_CHANGED, detail="hash mismatch"))

    return DriftReport(
        items=score_report_items(items),
        expected_count=len(expected),
        actual_count=len(actual),
        source_labels=source_labels or [],
        target_label=target_label,
    )
