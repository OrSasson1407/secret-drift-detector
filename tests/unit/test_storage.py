import pytest
from detector.storage.snapshot import Storage
from detector.storage.history  import History
from detector.diff.models import DriftReport, DriftItem, DriftKind, Severity
from datetime import datetime, timezone


def _drift_report(n_items: int = 2, has_drift: bool = True) -> DriftReport:
    items = []
    if has_drift:
        items = [
            DriftItem(key="DB_PASSWORD", kind=DriftKind.VALUE_CHANGED,      severity=Severity.CRITICAL),
            DriftItem(key="REDIS_URL",   kind=DriftKind.MISSING_IN_RUNTIME, severity=Severity.WARN),
        ][:n_items]
    return DriftReport(
        items=items,
        expected_count=5,
        actual_count=4,
        sources=["vault:secret/app"],
        targets=["docker:web"],
    )


# ---------------------------------------------------------------------------
# Storage.save_report
# ---------------------------------------------------------------------------

def test_save_report_returns_id(clean_db):
    storage = Storage(db_path=clean_db)
    run_id  = storage.save_report(_drift_report())
    assert isinstance(run_id, int)
    assert run_id >= 1


def test_save_multiple_reports(clean_db):
    storage = Storage(db_path=clean_db)
    id1 = storage.save_report(_drift_report(has_drift=True))
    id2 = storage.save_report(_drift_report(has_drift=False))
    assert id2 > id1


# ---------------------------------------------------------------------------
# History.list_runs
# ---------------------------------------------------------------------------

def test_list_runs_returns_all(clean_db):
    storage = Storage(db_path=clean_db)
    for _ in range(5):
        storage.save_report(_drift_report())
    hist = History(db_path=clean_db)
    runs = hist.list_runs(limit=10)
    assert len(runs) == 5


def test_list_runs_respects_limit(clean_db):
    storage = Storage(db_path=clean_db)
    for _ in range(10):
        storage.save_report(_drift_report())
    hist = History(db_path=clean_db)
    runs = hist.list_runs(limit=3)
    assert len(runs) == 3


def test_list_runs_only_drift_filter(clean_db):
    storage = Storage(db_path=clean_db)
    storage.save_report(_drift_report(has_drift=True))
    storage.save_report(_drift_report(has_drift=False))
    storage.save_report(_drift_report(has_drift=True))
    hist = History(db_path=clean_db)
    drift_runs = hist.list_runs(only_drift=True)
    assert all(r.has_drift for r in drift_runs)
    assert len(drift_runs) == 2


def test_list_runs_summary_fields(clean_db):
    storage = Storage(db_path=clean_db)
    storage.save_report(_drift_report())
    hist = History(db_path=clean_db)
    run  = hist.list_runs()[0]
    assert run.expected_count == 5
    assert run.actual_count   == 4
    assert run.drift_count    == 2
    assert run.has_drift      is True
    assert run.max_severity   == "critical"
    assert run.sources        == ["vault:secret/app"]
    assert run.targets        == ["docker:web"]


# ---------------------------------------------------------------------------
# History.get_run
# ---------------------------------------------------------------------------

def test_get_run_returns_full_report(clean_db):
    storage = Storage(db_path=clean_db)
    run_id  = storage.save_report(_drift_report())
    hist    = History(db_path=clean_db)
    detail  = hist.get_run(run_id)
    assert detail is not None
    assert "report_json" in detail
    assert detail["report_json"]["expected_count"] == 5


def test_get_run_not_found(clean_db):
    hist = History(db_path=clean_db)
    assert hist.get_run(9999) is None


# ---------------------------------------------------------------------------
# History.drift_trend
# ---------------------------------------------------------------------------

def test_drift_trend_order(clean_db):
    """Trend should be oldest-first (ascending) for charting."""
    storage = Storage(db_path=clean_db)
    storage.save_report(_drift_report(has_drift=True))
    storage.save_report(_drift_report(has_drift=False))
    hist  = History(db_path=clean_db)
    trend = hist.drift_trend(limit=10)
    assert len(trend) == 2
    assert trend[0]["id"] < trend[1]["id"]


def test_drift_trend_contains_required_keys(clean_db):
    storage = Storage(db_path=clean_db)
    storage.save_report(_drift_report())
    hist  = History(db_path=clean_db)
    point = hist.drift_trend()[0]
    for key in ("id", "timestamp", "drift_count", "has_drift", "max_severity"):
        assert key in point
