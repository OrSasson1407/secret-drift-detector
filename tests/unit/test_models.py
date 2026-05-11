import pytest
from detector.diff.models import Severity, DriftItem, DriftReport, DriftKind


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH     > Severity.WARN
    assert Severity.WARN     > Severity.INFO
    assert Severity.CRITICAL >= Severity.CRITICAL


def test_severity_rank_unique():
    ranks = [s.rank for s in Severity]
    assert len(ranks) == len(set(ranks))


# ---------------------------------------------------------------------------
# DriftReport helpers
# ---------------------------------------------------------------------------

def _make_report(*severities) -> DriftReport:
    items = [
        DriftItem(key=f"KEY_{i}", kind=DriftKind.VALUE_CHANGED, severity=s)
        for i, s in enumerate(severities)
    ]
    return DriftReport(items=items, expected_count=len(items), actual_count=len(items))


def test_has_drift_true():
    r = _make_report(Severity.WARN)
    assert r.has_drift


def test_has_drift_false():
    r = DriftReport(items=[], expected_count=2, actual_count=2)
    assert not r.has_drift


def test_max_severity_picks_highest():
    r = _make_report(Severity.INFO, Severity.HIGH, Severity.WARN)
    assert r.max_severity == Severity.HIGH


def test_max_severity_none_when_empty():
    r = DriftReport(items=[], expected_count=0, actual_count=0)
    assert r.max_severity is None


def test_items_at_or_above_filters_correctly():
    r = _make_report(Severity.INFO, Severity.WARN, Severity.HIGH, Severity.CRITICAL)
    assert len(r.items_at_or_above(Severity.HIGH)) == 2
    assert len(r.items_at_or_above(Severity.WARN)) == 3
    assert len(r.items_at_or_above(Severity.INFO)) == 4
    assert len(r.items_at_or_above(Severity.CRITICAL)) == 1


def test_report_serialises_to_json():
    r = _make_report(Severity.CRITICAL)
    data = r.model_dump_json()
    assert "critical" in data
