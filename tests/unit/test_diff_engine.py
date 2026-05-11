from detector.diff.engine import compute_drift
from detector.diff.models import DriftKind

def test_compute_drift_no_change():
    expected = {"DB_PASS": "hash1", "API_KEY": "hash2"}
    actual = {"DB_PASS": "hash1", "API_KEY": "hash2"}
    report = compute_drift(expected, actual)
    assert not report.has_drift
    assert len(report.items) == 0

def test_compute_drift_missing_in_runtime():
    expected = {"DB_PASS": "hash1", "API_KEY": "hash2"}
    actual = {"DB_PASS": "hash1"}
    report = compute_drift(expected, actual)
    assert report.has_drift
    assert report.items[0].key == "API_KEY"
    assert report.items[0].kind == DriftKind.MISSING_IN_RUNTIME

def test_compute_drift_value_changed():
    expected = {"DB_PASS": "hash1"}
    actual = {"DB_PASS": "hash2"}
    report = compute_drift(expected, actual)
    assert report.has_drift
    assert report.items[0].kind == DriftKind.VALUE_CHANGED
