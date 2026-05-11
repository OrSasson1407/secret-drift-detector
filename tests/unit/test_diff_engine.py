import pytest
from detector.diff.engine import compute_drift
from detector.diff.models import DriftKind, Severity
from tests.conftest import make_expected, make_actual


# ---------------------------------------------------------------------------
# No drift
# ---------------------------------------------------------------------------

def test_no_drift_empty():
    report = compute_drift({}, {})
    assert not report.has_drift
    assert report.expected_count == 0
    assert report.actual_count == 0


def test_no_drift_matching():
    e = make_expected("DB_PASSWORD", "abc", "API_KEY", "xyz")
    a = make_actual("DB_PASSWORD", "abc", "API_KEY", "xyz")
    report = compute_drift(e, a)
    assert not report.has_drift
    assert len(report.items) == 0


# ---------------------------------------------------------------------------
# Missing in runtime
# ---------------------------------------------------------------------------

def test_missing_in_runtime():
    e = make_expected("DB_PASSWORD", "abc", "API_KEY", "xyz")
    a = make_actual("DB_PASSWORD", "abc")
    report = compute_drift(e, a)
    assert report.has_drift
    keys = {i.key for i in report.items}
    assert "API_KEY" in keys
    item = next(i for i in report.items if i.key == "API_KEY")
    assert item.kind == DriftKind.MISSING_IN_RUNTIME


def test_missing_key_severity_critical():
    e = make_expected("DATABASE_PASSWORD", "s3cr3t")
    a = {}
    report = compute_drift(e, a)
    assert report.items[0].severity == Severity.CRITICAL


def test_missing_key_severity_high():
    e = make_expected("AUTH_TOKEN", "tok")
    a = {}
    report = compute_drift(e, a)
    assert report.items[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Extra in runtime
# ---------------------------------------------------------------------------

def test_extra_in_runtime():
    e = make_expected("DB_PASSWORD", "abc")
    a = make_actual("DB_PASSWORD", "abc", "GHOST_VAR", "ghost")
    report = compute_drift(e, a)
    assert report.has_drift
    item = next(i for i in report.items if i.key == "GHOST_VAR")
    assert item.kind == DriftKind.EXTRA_IN_RUNTIME


def test_extra_critical_pattern_capped_at_high():
    """EXTRA items matching CRITICAL patterns should be capped at HIGH."""
    e = {}
    a = make_actual("DATABASE_PASSWORD", "leaked")
    report = compute_drift(e, a)
    item = report.items[0]
    assert item.kind == DriftKind.EXTRA_IN_RUNTIME
    assert item.severity == Severity.HIGH  # not CRITICAL


# ---------------------------------------------------------------------------
# Value changed
# ---------------------------------------------------------------------------

def test_value_changed():
    e = make_expected("DB_PASSWORD", "old")
    a = make_actual("DB_PASSWORD", "new")
    report = compute_drift(e, a)
    assert report.has_drift
    item = report.items[0]
    assert item.kind == DriftKind.VALUE_CHANGED
    assert item.severity == Severity.CRITICAL


def test_value_changed_non_secret():
    e = make_expected("APP_NAME", "old")
    a = make_actual("APP_NAME", "new")
    report = compute_drift(e, a)
    assert report.items[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Mixed drift
# ---------------------------------------------------------------------------

def test_mixed_drift(sample_expected, sample_actual_with_drift):
    report = compute_drift(sample_expected, sample_actual_with_drift)
    assert report.has_drift

    kinds = {i.kind for i in report.items}
    assert DriftKind.MISSING_IN_RUNTIME in kinds
    assert DriftKind.EXTRA_IN_RUNTIME   in kinds
    assert DriftKind.VALUE_CHANGED      in kinds


def test_max_severity(sample_expected, sample_actual_with_drift):
    report = compute_drift(sample_expected, sample_actual_with_drift)
    assert report.max_severity == Severity.CRITICAL


def test_items_at_or_above(sample_expected, sample_actual_with_drift):
    report = compute_drift(sample_expected, sample_actual_with_drift)
    critical_items = report.items_at_or_above(Severity.CRITICAL)
    assert all(i.severity == Severity.CRITICAL for i in critical_items)


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------

def test_counts():
    e = make_expected("A", "1", "B", "2", "C", "3")
    a = make_actual("A", "1", "B", "2")
    report = compute_drift(e, a)
    assert report.expected_count == 3
    assert report.actual_count   == 2


# ---------------------------------------------------------------------------
# Metadata passthrough
# ---------------------------------------------------------------------------

def test_sources_and_targets_passed_through():
    report = compute_drift({}, {}, sources=["vault:sec/app"], targets=["docker:web"])
    assert report.sources == ["vault:sec/app"]
    assert report.targets == ["docker:web"]


def test_checked_at_is_set():
    from datetime import timezone
    report = compute_drift({}, {})
    assert report.checked_at.tzinfo == timezone.utc
