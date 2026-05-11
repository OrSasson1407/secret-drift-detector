"""
Integration test: full source → diff → storage → history round-trip.
No external services required — uses DotEnvSource + LocalEnvProber + SQLite.
"""
import os
import tempfile
import pytest

from detector.sources.dotenv_file import DotEnvSource
from detector.sources              import _hash
from detector.runtime.local_env    import LocalEnvProber
from detector.diff.engine          import compute_drift
from detector.diff.models          import DriftKind, Severity
from detector.storage.snapshot     import Storage
from detector.storage.history      import History


@pytest.fixture
def env_file(tmp_path):
    p = tmp_path / ".env.test"
    p.write_text("DB_PASSWORD=hunter2\nAPP_NAME=myapp\nSTRIPE_SECRET_KEY=sk_live_xyz\n")
    return str(p)


@pytest.mark.asyncio
async def test_full_round_trip_no_drift(env_file, clean_db, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD",       "hunter2")
    monkeypatch.setenv("APP_NAME",          "myapp")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz")

    src  = DotEnvSource(path=env_file)
    snap = await src.masked_fetch()

    prober = LocalEnvProber(key_filter=["DB_PASSWORD", "APP_NAME", "STRIPE_SECRET_KEY"])
    raw    = await prober.probe()
    actual = {k: _hash(v) for k, v in raw.items()}

    report = compute_drift(snap.secrets, actual,
                           sources=[snap.source], targets=["local_env"])
    assert not report.has_drift

    storage = Storage(db_path=clean_db)
    run_id  = storage.save_report(report)
    hist    = History(db_path=clean_db)
    detail  = hist.get_run(run_id)
    assert detail["has_drift"] == 0


@pytest.mark.asyncio
async def test_full_round_trip_with_drift(env_file, clean_db, monkeypatch):
    # Runtime has a changed password and is missing the Stripe key
    monkeypatch.setenv("DB_PASSWORD", "changed_password")
    monkeypatch.setenv("APP_NAME",    "myapp")
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

    src  = DotEnvSource(path=env_file)
    snap = await src.masked_fetch()

    prober = LocalEnvProber(key_filter=["DB_PASSWORD", "APP_NAME", "STRIPE_SECRET_KEY"])
    raw    = await prober.probe()
    actual = {k: _hash(v) for k, v in raw.items()}

    report = compute_drift(snap.secrets, actual,
                           sources=[snap.source], targets=["local_env"])
    assert report.has_drift

    kinds = {i.kind for i in report.items}
    assert DriftKind.VALUE_CHANGED      in kinds
    assert DriftKind.MISSING_IN_RUNTIME in kinds
    assert report.max_severity == Severity.CRITICAL

    storage = Storage(db_path=clean_db)
    storage.save_report(report)
    hist  = History(db_path=clean_db)
    trend = hist.drift_trend()
    assert trend[0]["has_drift"] == 1


@pytest.mark.asyncio
async def test_trend_across_multiple_runs(env_file, clean_db, monkeypatch):
    storage = Storage(db_path=clean_db)

    # Run 1: no drift
    monkeypatch.setenv("DB_PASSWORD", "hunter2")
    monkeypatch.setenv("APP_NAME",    "myapp")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz")
    src  = DotEnvSource(path=env_file)
    snap = await src.masked_fetch()
    prober = LocalEnvProber(key_filter=list(snap.secrets.keys()))
    raw    = await prober.probe()
    actual = {k: _hash(v) for k, v in raw.items()}
    storage.save_report(compute_drift(snap.secrets, actual))

    # Run 2: drift
    monkeypatch.setenv("DB_PASSWORD", "rotated!")
    raw2   = await prober.probe()
    actual2 = {k: _hash(v) for k, v in raw2.items()}
    storage.save_report(compute_drift(snap.secrets, actual2))

    hist  = History(db_path=clean_db)
    trend = hist.drift_trend()
    assert len(trend) == 2
    assert trend[0]["has_drift"] == 0
    assert trend[1]["has_drift"] == 1
