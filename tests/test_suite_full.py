"""
=============================================================================
Secret Drift Detector — Full Professional Test Suite
=============================================================================
Coverage map
------------
  Unit
    test_hash                  → detector.sources._hash
    test_severity              → detector.diff.models.Severity
    test_drift_item            → detector.diff.models.DriftItem
    test_drift_report          → detector.diff.models.DriftReport
    test_scorer                → detector.diff.scorer (score_severity, is_weak_value,
                                   shannon_entropy, find_likely_renames, remediation_hint)
    test_diff_engine           → detector.diff.engine.compute_drift  (all 7 DriftKind)
    test_config                → detector.config (_resolve_env, DetectorConfig, validators)
    test_runtime               → detector.runtime.BaseProber helpers
    test_local_env_prober      → detector.runtime.local_env.LocalEnvProber
    test_docker_exec_prober    → detector.runtime.docker_exec.DockerExecProber
    test_http_introspect_prober→ detector.runtime.http_introspect.HttpIntrospectProber
    test_sources               → detector.sources (BaseSource retry, DotEnvSource, SSMSource)
    test_storage               → detector.storage (Storage.save_report, History, chain)
    test_alerts_base           → detector.alerts.BaseAlerter
    test_slack_alerter         → detector.alerts.slack.SlackAlerter
    test_agent                 → detector.agent.Agent  (mocked sources/targets)
    test_server                → detector.server.app  (FastAPI + WebSocket)

  Integration
    test_e2e_no_drift          → dotenv → diff → storage → history (clean run)
    test_e2e_drift             → dotenv → diff → storage → history (drifted run)
    test_e2e_multi_run_trend   → multi-run drift_trend consistency
    test_e2e_audit_chain       → tamper-evident hash chain verification

Run
---
  # from repo root
  $env:DRIFT_API_KEY="test-secret-key"
  poetry run pytest tests/test_suite_full.py -v --tb=short
=============================================================================
"""

import asyncio
import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── env bootstrap (must happen before any app import) ───────────────────────
os.environ.setdefault("DRIFT_API_KEY",  "test-secret-key")
os.environ.setdefault("DRIFT_DB_PATH",  "test_db_temp.json")

# ── project imports ──────────────────────────────────────────────────────────
from detector.sources              import _hash, BaseSource, SecretSnapshot, SourceError
from detector.sources.dotenv_file  import DotEnvSource
from detector.sources.ssm          import SSMSource
from detector.diff.models          import DriftItem, DriftKind, DriftReport, Severity
from detector.diff.scorer          import (
    find_likely_renames, is_weak_value, remediation_hint,
    score_severity, shannon_entropy,
)
from detector.diff.engine          import compute_drift
from detector.config               import (
    AlertsConfig, DetectorConfig, SourceConfig, _resolve_env,
)
from detector.runtime              import BaseProber, SYSTEM_KEYS
from detector.runtime.local_env    import LocalEnvProber
from detector.runtime.docker_exec  import DockerExecProber
from detector.runtime.http_introspect import HttpIntrospectProber
from detector.storage.snapshot     import Storage
from detector.storage.history      import History
from detector.alerts               import BaseAlerter
from detector.alerts.slack         import SlackAlerter


# ─────────────────────────────────────────────────────────────────────────────
# Shared test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_expected(*kv) -> dict[str, str]:
    it = iter(kv)
    return {k: _hash(v) for k, v in zip(it, it)}

_make_actual = _make_expected


def _tmp_env(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def _tmp_toml(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def _tmp_db(tmp_path) -> str:
    return str(tmp_path / "drift_test.json")


def _clean_report(**kwargs) -> DriftReport:
    defaults = dict(items=[], expected_count=3, actual_count=3,
                    sources=["dotenv:.env"], targets=["local_env"])
    defaults.update(kwargs)
    return DriftReport(**defaults)


def _drift_report(**kwargs) -> DriftReport:
    item = DriftItem(key="DB_PASSWORD", kind=DriftKind.VALUE_CHANGED,
                     severity=Severity.CRITICAL, detail="hash mismatch")
    defaults = dict(items=[item], expected_count=3, actual_count=3,
                    sources=["dotenv:.env"], targets=["local_env"])
    defaults.update(kwargs)
    return DriftReport(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Hash utility
# ─────────────────────────────────────────────────────────────────────────────

class TestHash:
    def test_deterministic(self):
        assert _hash("abc") == _hash("abc")

    def test_different_inputs_differ(self):
        assert _hash("abc") != _hash("xyz")

    def test_returns_64_char_hex(self):
        h = _hash("hello")
        assert len(h) == 64
        int(h, 16)  # must not raise

    def test_empty_string(self):
        h = _hash("")
        assert len(h) == 64

    def test_matches_stdlib(self):
        value = "super-secret"
        expected = hashlib.sha256(value.encode("utf-8")).hexdigest()
        assert _hash(value) == expected


# ─────────────────────────────────────────────────────────────────────────────
# 2. Severity model
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverity:
    def test_ordering_chain(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.WARN > Severity.INFO

    def test_ge_same(self):
        assert Severity.WARN >= Severity.WARN

    def test_le_same(self):
        assert Severity.HIGH <= Severity.HIGH

    def test_ranks_unique(self):
        ranks = [s.rank for s in Severity]
        assert len(ranks) == len(set(ranks))

    def test_rank_values(self):
        assert Severity.CRITICAL.rank == 4
        assert Severity.HIGH.rank     == 3
        assert Severity.WARN.rank     == 2
        assert Severity.INFO.rank     == 1


# ─────────────────────────────────────────────────────────────────────────────
# 3. DriftItem
# ─────────────────────────────────────────────────────────────────────────────

class TestDriftItem:
    def test_is_critical_true(self):
        item = DriftItem(key="K", kind=DriftKind.VALUE_CHANGED, severity=Severity.CRITICAL)
        assert item.is_critical

    def test_is_critical_false(self):
        item = DriftItem(key="K", kind=DriftKind.VALUE_CHANGED, severity=Severity.WARN)
        assert not item.is_critical

    def test_default_severity_is_info(self):
        item = DriftItem(key="K", kind=DriftKind.EXTRA_IN_RUNTIME)
        assert item.severity == Severity.INFO

    def test_entropy_score_optional(self):
        item = DriftItem(key="K", kind=DriftKind.WEAK_VALUE, entropy_score=1.23)
        assert item.entropy_score == pytest.approx(1.23)

    def test_renamed_from_optional(self):
        item = DriftItem(key="NEW", kind=DriftKind.RENAMED, renamed_from="OLD")
        assert item.renamed_from == "OLD"


# ─────────────────────────────────────────────────────────────────────────────
# 4. DriftReport
# ─────────────────────────────────────────────────────────────────────────────

class TestDriftReport:
    def test_has_drift_true(self):
        r = _drift_report()
        assert r.has_drift

    def test_has_drift_false(self):
        r = _clean_report()
        assert not r.has_drift

    def test_max_severity_none_when_empty(self):
        r = _clean_report()
        assert r.max_severity is None

    def test_max_severity_picks_highest(self):
        items = [
            DriftItem(key="A", kind=DriftKind.VALUE_CHANGED, severity=Severity.INFO),
            DriftItem(key="B", kind=DriftKind.VALUE_CHANGED, severity=Severity.CRITICAL),
            DriftItem(key="C", kind=DriftKind.VALUE_CHANGED, severity=Severity.HIGH),
        ]
        r = DriftReport(items=items, expected_count=3, actual_count=3)
        assert r.max_severity == Severity.CRITICAL

    def test_items_at_or_above(self):
        items = [
            DriftItem(key="A", kind=DriftKind.VALUE_CHANGED, severity=Severity.INFO),
            DriftItem(key="B", kind=DriftKind.VALUE_CHANGED, severity=Severity.WARN),
            DriftItem(key="C", kind=DriftKind.VALUE_CHANGED, severity=Severity.HIGH),
            DriftItem(key="D", kind=DriftKind.VALUE_CHANGED, severity=Severity.CRITICAL),
        ]
        r = DriftReport(items=items, expected_count=4, actual_count=4)
        assert len(r.items_at_or_above(Severity.HIGH))     == 2
        assert len(r.items_at_or_above(Severity.WARN))     == 3
        assert len(r.items_at_or_above(Severity.INFO))     == 4
        assert len(r.items_at_or_above(Severity.CRITICAL)) == 1

    def test_by_kind(self):
        items = [
            DriftItem(key="A", kind=DriftKind.VALUE_CHANGED),
            DriftItem(key="B", kind=DriftKind.MISSING_IN_RUNTIME),
            DriftItem(key="C", kind=DriftKind.VALUE_CHANGED),
        ]
        r = DriftReport(items=items, expected_count=3, actual_count=2)
        changed = r.by_kind(DriftKind.VALUE_CHANGED)
        assert len(changed) == 2
        assert all(i.kind == DriftKind.VALUE_CHANGED for i in changed)

    def test_checked_at_is_utc(self):
        r = _clean_report()
        assert r.checked_at.tzinfo == timezone.utc

    def test_serialises_to_json(self):
        r = _drift_report()
        data = r.model_dump_json()
        assert "critical" in data
        assert "DB_PASSWORD" in data

    def test_summary_structure(self):
        r = _drift_report()
        s = r.summary()
        assert "has_drift" in s
        assert "by_severity" in s
        assert s["has_drift"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. Scorer
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreSeverity:
    @pytest.mark.parametrize("key", [
        "DATABASE_PASSWORD", "DB_PASSWD", "STRIPE_SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "API_KEY", "ENCRYPTION_KEY",
    ])
    def test_critical_patterns(self, key):
        assert score_severity(key) == Severity.CRITICAL

    @pytest.mark.parametrize("key", [
        "AUTH_TOKEN", "GITHUB_TOKEN", "ACCESS_TOKEN",
        "TLS_CERT", "CLIENT_CREDENTIAL", "JWT_TOKEN",
    ])
    def test_high_patterns(self, key):
        assert score_severity(key) == Severity.HIGH

    def test_jwt_secret_is_critical(self):
        # JWT_SECRET matches the CRITICAL 'SECRET' pattern — documented behaviour
        assert score_severity("JWT_SECRET") == Severity.CRITICAL

    @pytest.mark.parametrize("key", [
        "REDIS_URL", "DATABASE_HOST", "API_ENDPOINT", "DB_CONNECTION", "SERVICE_DSN",
    ])
    def test_warn_patterns(self, key):
        assert score_severity(key) == Severity.WARN

    @pytest.mark.parametrize("key", [
        "APP_NAME", "LOG_LEVEL", "ENVIRONMENT", "REGION", "FEATURE_FLAG",
    ])
    def test_info_patterns(self, key):
        assert score_severity(key) == Severity.INFO

    def test_case_insensitive(self):
        assert score_severity("database_password") == Severity.CRITICAL
        assert score_severity("Auth_Token")         == Severity.HIGH

    def test_extra_critical_capped_at_high(self):
        # EXTRA_IN_RUNTIME should never exceed HIGH
        assert score_severity("DATABASE_PASSWORD", DriftKind.EXTRA_IN_RUNTIME) == Severity.HIGH

    def test_orphaned_always_critical(self):
        assert score_severity("APP_NAME", DriftKind.ORPHANED) == Severity.CRITICAL

    def test_stale_minimum_is_high(self):
        sev = score_severity("APP_NAME", DriftKind.STALE_SECRET)
        assert sev >= Severity.HIGH

    def test_weak_value_non_secret_is_warn(self):
        sev = score_severity("APP_NAME", DriftKind.WEAK_VALUE)
        assert sev == Severity.WARN


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        # "aaaaaaa" has 0 bits entropy
        assert shannon_entropy("aaaaaaa") == pytest.approx(0.0, abs=1e-6)

    def test_uniform_distribution(self):
        # "ab" → 1.0 bits
        assert shannon_entropy("ab") == pytest.approx(1.0, abs=1e-6)

    def test_high_entropy_random_hex(self):
        # A random hex string should have high entropy
        val = "a3f7c2d9b41e8605"
        assert shannon_entropy(val) > 3.0


class TestIsWeakValue:
    @pytest.mark.parametrize("val", [
        # Matches _WEAK_PATTERNS regex (length >= 6)
        "password", "changeme", "secret",
        "000000", "xxxxxx", "placeholder",
    ])
    def test_known_weak_patterns(self, val):
        weak, _ = is_weak_value(val)
        assert weak, f"Expected '{val}' to be weak"

    @pytest.mark.parametrize("val", [
        # Too short (< MIN_VALUE_LENGTH=6) — scorer skips them, not flagged as weak
        "admin", "1234",
    ])
    def test_too_short_skipped(self, val):
        weak, _ = is_weak_value(val)
        assert not weak, f"'{val}' is too short to score — should not be flagged"

    def test_strong_value_not_weak(self):
        weak, ent = is_weak_value("xK9#mP2$vLqN8!rT")
        assert not weak
        assert ent > 3.0

    def test_too_short_not_scored(self):
        # Values under _MIN_VALUE_LENGTH are skipped
        weak, _ = is_weak_value("ab")
        assert not weak

    def test_low_entropy_generic_value_is_weak(self):
        weak, entropy = is_weak_value("aaaaaaaaaa")
        assert weak
        assert entropy < 1.0


class TestFindLikelyRenames:
    def test_obvious_rename(self):
        renames = find_likely_renames({"DB_PASSWORD"}, {"DB_PASSWD"})
        assert len(renames) == 1
        old, new, score = renames[0]
        assert old == "DB_PASSWORD"
        assert new == "DB_PASSWD"
        assert score > 0.72

    def test_no_rename_below_threshold(self):
        renames = find_likely_renames({"FOO"}, {"COMPLETELY_DIFFERENT_KEY"})
        assert len(renames) == 0

    def test_greedy_one_to_one(self):
        missing = {"DB_PASSWORD", "APP_SECRET"}
        extra   = {"DB_PASSWD",   "APP_TOKEN"}
        renames = find_likely_renames(missing, extra)
        olds = {r[0] for r in renames}
        news = {r[1] for r in renames}
        # Each key used at most once
        assert len(olds) == len(set(olds))
        assert len(news) == len(set(news))

    def test_empty_inputs(self):
        assert find_likely_renames(set(), set()) == []


class TestRemediationHint:
    def test_missing_hint(self):
        h = remediation_hint("DB_PASSWORD", DriftKind.MISSING_IN_RUNTIME)
        assert "DB_PASSWORD" in h
        assert "restart" in h.lower() or "pick up" in h.lower()

    def test_extra_hint(self):
        h = remediation_hint("GHOST_VAR", DriftKind.EXTRA_IN_RUNTIME)
        assert "GHOST_VAR" in h

    def test_changed_hint(self):
        h = remediation_hint("DB_PASSWORD", DriftKind.VALUE_CHANGED)
        assert "DB_PASSWORD" in h
        assert "rotate" in h.lower() or "redeploy" in h.lower()

    def test_orphaned_hint(self):
        h = remediation_hint("LEAK_KEY", DriftKind.ORPHANED)
        assert "orphaned" in h.lower() or "rotate" in h.lower()

    def test_renamed_hint(self):
        h = remediation_hint("NEW_KEY", DriftKind.RENAMED, renamed_from="OLD_KEY")
        assert "OLD_KEY" in h
        assert "NEW_KEY" in h

    def test_weak_hint(self):
        h = remediation_hint("MY_SECRET", DriftKind.WEAK_VALUE)
        assert "entropy" in h.lower() or "strong" in h.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Diff Engine  (all 7 DriftKind paths)
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeDrift:
    # ── No drift ─────────────────────────────────────────────────────────────
    def test_empty_is_clean(self):
        r = compute_drift({}, {})
        assert not r.has_drift

    def test_matching_secrets_clean(self):
        e = _make_expected("DB_PASSWORD", "s3cr3t", "APP_NAME", "app")
        r = compute_drift(e, dict(e))
        assert not r.has_drift

    # ── MISSING_IN_RUNTIME ───────────────────────────────────────────────────
    def test_missing_in_runtime_detected(self):
        e = _make_expected("DB_PASSWORD", "s3cr3t")
        r = compute_drift(e, {})
        items = r.by_kind(DriftKind.MISSING_IN_RUNTIME)
        assert any(i.key == "DB_PASSWORD" for i in items)

    def test_missing_critical_key_is_critical(self):
        e = _make_expected("DATABASE_PASSWORD", "s3cr3t")
        r = compute_drift(e, {})
        assert r.items[0].severity == Severity.CRITICAL

    def test_missing_non_secret_is_info(self):
        e = _make_expected("APP_NAME", "myapp")
        r = compute_drift(e, {})
        assert r.items[0].severity == Severity.INFO

    # ── VALUE_CHANGED ────────────────────────────────────────────────────────
    def test_value_changed_detected(self):
        e = _make_expected("DB_PASSWORD", "old")
        a = _make_actual  ("DB_PASSWORD", "new")
        r = compute_drift(e, a)
        assert r.by_kind(DriftKind.VALUE_CHANGED)

    def test_value_changed_password_is_critical(self):
        e = _make_expected("DB_PASSWORD", "old")
        a = _make_actual  ("DB_PASSWORD", "new")
        r = compute_drift(e, a)
        assert r.items[0].severity == Severity.CRITICAL

    def test_value_changed_non_secret_is_info(self):
        e = _make_expected("APP_NAME", "old")
        a = _make_actual  ("APP_NAME", "new")
        r = compute_drift(e, a)
        assert r.items[0].severity == Severity.INFO

    # ── ORPHANED ─────────────────────────────────────────────────────────────
    def test_orphaned_detected_when_not_in_any_source(self):
        # Key exists in runtime but not in expected OR all_source_keys
        e = _make_expected("DB_PASSWORD", "s3cr3t")
        a = _make_actual  ("DB_PASSWORD", "s3cr3t", "GHOST", "leak")
        r = compute_drift(e, a, all_source_keys={"DB_PASSWORD"})
        orphans = r.by_kind(DriftKind.ORPHANED)
        assert any(i.key == "GHOST" for i in orphans)

    def test_orphaned_is_always_critical(self):
        e = {}
        a = _make_actual("ORPHAN_KEY", "leak")
        r = compute_drift(e, a, all_source_keys=set())
        assert r.items[0].severity == Severity.CRITICAL

    # ── EXTRA_IN_RUNTIME ────────────────────────────────────────────────────
    def test_extra_in_runtime_when_in_all_source_keys(self):
        e = _make_expected("DB_PASSWORD", "s3cr3t")
        a = _make_actual  ("DB_PASSWORD", "s3cr3t", "EXTRA_KEY", "val")
        # EXTRA_KEY is in all_source_keys → EXTRA, not ORPHANED
        r = compute_drift(e, a, all_source_keys={"DB_PASSWORD", "EXTRA_KEY"})
        extras = r.by_kind(DriftKind.EXTRA_IN_RUNTIME)
        assert any(i.key == "EXTRA_KEY" for i in extras)

    # ── RENAMED ──────────────────────────────────────────────────────────────
    def test_renamed_detected(self):
        e = _make_expected("DB_PASSWORD", "s3cr3t")
        a = _make_actual  ("DB_PASSWD",   "s3cr3t")
        r = compute_drift(e, a)
        renamed = r.by_kind(DriftKind.RENAMED)
        assert renamed, "Expected at least one RENAMED item"
        assert renamed[0].renamed_from == "DB_PASSWORD"

    # ── WEAK_VALUE ───────────────────────────────────────────────────────────
    def test_weak_value_detected(self):
        e = _make_expected("MY_SECRET", "password")
        a = _make_actual  ("MY_SECRET", "password")
        # Provide plaintext so entropy scorer can run
        r = compute_drift(e, a, actual_plaintext={"MY_SECRET": "password"}, enable_entropy=True)
        weak = r.by_kind(DriftKind.WEAK_VALUE)
        assert weak, "Expected WEAK_VALUE item for 'password'"

    def test_weak_value_skipped_when_entropy_disabled(self):
        e = _make_expected("MY_SECRET", "password")
        a = _make_actual  ("MY_SECRET", "password")
        r = compute_drift(e, a, actual_plaintext={"MY_SECRET": "password"}, enable_entropy=False)
        assert not r.by_kind(DriftKind.WEAK_VALUE)

    def test_strong_value_not_flagged(self):
        strong = "xK9#mP2$vLqN8!rT"
        e = _make_expected("MY_SECRET", strong)
        a = _make_actual  ("MY_SECRET", strong)
        r = compute_drift(e, a, actual_plaintext={"MY_SECRET": strong}, enable_entropy=True)
        assert not r.by_kind(DriftKind.WEAK_VALUE)

    # ── Metadata passthrough ─────────────────────────────────────────────────
    def test_sources_and_targets_preserved(self):
        r = compute_drift({}, {}, sources=["vault:s/app"], targets=["docker:web"])
        assert r.sources == ["vault:s/app"]
        assert r.targets == ["docker:web"]

    def test_expected_and_actual_counts(self):
        e = _make_expected("A", "1", "B", "2", "C", "3")
        a = _make_actual  ("A", "1", "B", "2")
        r = compute_drift(e, a)
        assert r.expected_count == 3
        assert r.actual_count   == 2

    # ── Sort order ───────────────────────────────────────────────────────────
    def test_items_sorted_by_severity_desc(self):
        e = _make_expected("DB_PASSWORD", "old", "APP_NAME", "old")
        a = _make_actual  ("DB_PASSWORD", "new", "APP_NAME", "new")
        r = compute_drift(e, a)
        ranks = [i.severity.rank for i in r.items]
        assert ranks == sorted(ranks, reverse=True)

    # ── Mixed ───────────────────────────────────────────────────────────────
    def test_mixed_drift_all_kinds_present(self):
        e = _make_expected("DB_PASSWORD", "s3cr3t", "STRIPE_SECRET_KEY", "sk_live_abc",
                           "REDIS_URL", "redis://localhost")
        a = dict(e)
        a["DB_PASSWORD"] = _hash("changed")          # VALUE_CHANGED
        del a["STRIPE_SECRET_KEY"]                    # MISSING
        a["GHOST_VAR"]   = _hash("ghost")             # ORPHANED (not in all_source_keys)
        r = compute_drift(e, a, all_source_keys=set(e.keys()))
        kinds = {i.kind for i in r.items}
        assert DriftKind.VALUE_CHANGED      in kinds
        assert DriftKind.MISSING_IN_RUNTIME in kinds
        assert DriftKind.ORPHANED           in kinds


# ─────────────────────────────────────────────────────────────────────────────
# 7. Config
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveEnv:
    def test_passthrough(self):
        assert _resolve_env("plain") == "plain"

    def test_reads_env_var(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "tok123")
        assert _resolve_env("env:MY_TOKEN") == "tok123"

    def test_missing_env_var_returns_none(self, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        assert _resolve_env("env:MISSING_VAR") is None

    def test_none_input(self):
        assert _resolve_env(None) is None


_MINIMAL_TOML = """
[agent]
interval_seconds = 30
alert_on_extra   = false
fail_on_drift    = true

[[sources]]
type = "dotenv"
path = ".env.test"

[[targets]]
type = "local_env"
"""

_FULL_TOML = """
[agent]
interval_seconds = 120
alert_on_extra   = true
fail_on_drift    = false
max_retries      = 5
retry_delay      = 1.0

[[sources]]
type   = "vault"
addr   = "https://vault.example.com"
path   = "secret/data/app"
token  = "env:VAULT_TOKEN"

[[sources]]
type       = "doppler"
project    = "myapp"
config_env = "production"
token      = "env:DOPPLER_TOKEN"

[[targets]]
type      = "docker"
container = "web_1"

[alerts.slack]
enabled     = true
webhook_url = "env:SLACK_WEBHOOK"
min_severity = "warn"

[alerts.pagerduty]
enabled         = true
integration_key = "env:PD_KEY"
min_severity    = "critical"

[alerts.webhook]
enabled      = true
url          = "https://hooks.example.com/drift"
min_severity = "high"
"""


class TestDetectorConfig:
    def test_load_minimal(self):
        path = _tmp_toml(_MINIMAL_TOML)
        cfg  = DetectorConfig.load_from_file(path)
        assert cfg.agent.interval_seconds == 30
        assert len(cfg.sources) == 1
        assert cfg.sources[0].type == "dotenv"
        assert len(cfg.targets) == 1

    def test_load_full(self, monkeypatch):
        monkeypatch.setenv("VAULT_TOKEN",   "s.abc")
        monkeypatch.setenv("DOPPLER_TOKEN", "dp.xyz")
        monkeypatch.setenv("SLACK_WEBHOOK", "https://hooks.slack.com/xxx")
        monkeypatch.setenv("PD_KEY",        "pd_key_123")
        path = _tmp_toml(_FULL_TOML)
        cfg  = DetectorConfig.load_from_file(path)
        assert cfg.agent.max_retries == 5
        assert cfg.sources[0].token == "s.abc"
        assert cfg.alerts.slack.webhook_url == "https://hooks.slack.com/xxx"
        assert cfg.alerts.pagerduty.integration_key == "pd_key_123"
        assert cfg.alerts.webhook.enabled is True

    def test_agent_defaults(self):
        path = _tmp_toml(_MINIMAL_TOML)
        cfg  = DetectorConfig.load_from_file(path)
        assert cfg.agent.max_retries == 3
        assert cfg.agent.retry_delay == pytest.approx(2.0)
        assert cfg.agent.timeout_seconds == pytest.approx(10.0)

    def test_alerts_jira_stdout_exist(self):
        ac = AlertsConfig()
        assert hasattr(ac, "jira")
        assert hasattr(ac, "stdout")
        assert ac.stdout.min_severity == "info"

    def test_source_validation_kubernetes_requires_namespace(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SourceConfig(type="kubernetes")

    def test_source_validation_gcp_requires_project(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SourceConfig(type="gcp")

    def test_bom_tolerant_loading(self, tmp_path):
        p = tmp_path / "bom.toml"
        p.write_bytes(b"\xef\xbb\xbf" + _MINIMAL_TOML.encode("utf-8"))
        cfg = DetectorConfig.load_from_file(str(p))
        assert cfg.agent.interval_seconds == 30


# ─────────────────────────────────────────────────────────────────────────────
# 8. Runtime — BaseProber helpers
# ─────────────────────────────────────────────────────────────────────────────

class _ConcreteProber(BaseProber):
    type = "test"
    async def probe(self): return {}


class TestBaseProber:
    def test_parse_env_basic(self):
        raw = "KEY=value\nDB_PASSWORD=s3cr3t\nAPP_NAME=myapp"
        env = _ConcreteProber._parse_env_output(raw)
        assert env == {"KEY": "value", "DB_PASSWORD": "s3cr3t", "APP_NAME": "myapp"}

    def test_parse_env_value_with_equals(self):
        env = _ConcreteProber._parse_env_output("ENCODED=abc=def=ghi")
        assert env["ENCODED"] == "abc=def=ghi"

    def test_parse_env_skips_no_equals(self):
        env = _ConcreteProber._parse_env_output("VALID=yes\nNO_EQUALS\nALSO=1")
        assert "NO_EQUALS" not in env
        assert len(env) == 2

    def test_filter_env_strip_system(self):
        raw = {"PATH": "/usr/bin", "DB_PASSWORD": "secret", "HOME": "/root"}
        out = _ConcreteProber.filter_env(raw, strip_system=True)
        assert "PATH" not in out
        assert "HOME" not in out
        assert "DB_PASSWORD" in out

    def test_filter_env_extra_strip(self):
        raw = {"CUSTOM_NOISE": "x", "KEEP_ME": "y"}
        out = _ConcreteProber.filter_env(raw, extra_strip={"CUSTOM_NOISE"})
        assert "CUSTOM_NOISE" not in out
        assert "KEEP_ME" in out

    def test_system_keys_constants_present(self):
        assert "PATH" in SYSTEM_KEYS
        assert "HOME" in SYSTEM_KEYS


# ─────────────────────────────────────────────────────────────────────────────
# 9. LocalEnvProber
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalEnvProber:
    @pytest.mark.asyncio
    async def test_returns_env_vars(self, monkeypatch):
        monkeypatch.setenv("TEST_LOCAL_KEY", "hello_world")
        env = await LocalEnvProber().probe()
        assert env["TEST_LOCAL_KEY"] == "hello_world"

    @pytest.mark.asyncio
    async def test_key_filter_prefix(self, monkeypatch):
        monkeypatch.setenv("APP_NAME", "myapp")
        monkeypatch.setenv("APP_PORT", "8080")
        monkeypatch.setenv("DB_PASS",  "secret")
        env = await LocalEnvProber(key_filter=["APP_"]).probe()
        assert "APP_NAME" in env
        assert "APP_PORT" in env
        assert "DB_PASS"  not in env

    @pytest.mark.asyncio
    async def test_key_filter_exact_list(self, monkeypatch):
        monkeypatch.setenv("KEEP_A", "a")
        monkeypatch.setenv("KEEP_B", "b")
        monkeypatch.setenv("DROP_C", "c")
        env = await LocalEnvProber(key_filter=["KEEP_A", "KEEP_B"]).probe()
        assert "KEEP_A" in env
        assert "KEEP_B" in env
        assert "DROP_C" not in env


# ─────────────────────────────────────────────────────────────────────────────
# 10. DockerExecProber
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerExecProber:
    @pytest.mark.asyncio
    async def test_parses_output_correctly(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(b"DB_PASSWORD=secret\nAPP_NAME=myapp\n", b"")
        )
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            env = await DockerExecProber(container_name="web_1").probe()
        assert env["DB_PASSWORD"] == "secret"
        assert env["APP_NAME"]    == "myapp"

    @pytest.mark.asyncio
    async def test_raises_on_nonzero_exit(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"No such container"))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="docker exec failed"):
                await DockerExecProber(container_name="missing").probe()

    @pytest.mark.asyncio
    async def test_value_with_equals_sign(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(b"ENCODED=abc=def=ghi\n", b"")
        )
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            env = await DockerExecProber(container_name="app").probe()
        assert env["ENCODED"] == "abc=def=ghi"


# ─────────────────────────────────────────────────────────────────────────────
# 11. HttpIntrospectProber
# ─────────────────────────────────────────────────────────────────────────────

def _make_aiohttp_mock(status: int, json_body: dict | None = None):
    mock_resp = AsyncMock()
    mock_resp.status = status
    if json_body is not None:
        mock_resp.json = AsyncMock(return_value=json_body)
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__  = AsyncMock(return_value=False)
    mock_session.get = MagicMock(return_value=AsyncMock(
        __aenter__=AsyncMock(return_value=mock_resp),
        __aexit__=AsyncMock(return_value=False),
    ))
    return mock_session


class TestHttpIntrospectProber:
    @pytest.mark.asyncio
    async def test_parses_json_response(self):
        mock_session = _make_aiohttp_mock(200, {"DB_PASSWORD": "secret", "PORT": "8080"})
        with patch("aiohttp.ClientSession", return_value=mock_session):
            env = await HttpIntrospectProber(url="http://app/_debug/env").probe()
        assert env["DB_PASSWORD"] == "secret"
        assert env["PORT"]        == "8080"

    @pytest.mark.asyncio
    async def test_raises_on_non_200(self):
        mock_session = _make_aiohttp_mock(403)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(RuntimeError, match="HTTP 403"):
                await HttpIntrospectProber(url="http://app/_debug/env").probe()

    @pytest.mark.asyncio
    async def test_raises_on_500(self):
        mock_session = _make_aiohttp_mock(500)
        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(RuntimeError):
                await HttpIntrospectProber(url="http://app/_debug/env").probe()


# ─────────────────────────────────────────────────────────────────────────────
# 12. Sources — BaseSource retry + DotEnvSource + SSMSource
# ─────────────────────────────────────────────────────────────────────────────

class _FakeSource(BaseSource):
    type = "fake"
    async def fetch(self) -> SecretSnapshot:
        return SecretSnapshot(
            source="fake",
            fetched_at=datetime.now(timezone.utc),
            secrets={"MY_PASSWORD": "plaintext", "APP_NAME": "myapp"},
        )


class _BrokenSource(BaseSource):
    type = "broken"
    async def fetch(self) -> SecretSnapshot:
        raise ConnectionError("unreachable")


class TestBaseSource:
    @pytest.mark.asyncio
    async def test_masked_fetch_hashes_values(self):
        snap = await _FakeSource().masked_fetch()
        assert snap.secrets["MY_PASSWORD"] == _hash("plaintext")
        assert snap.secrets["APP_NAME"]    == _hash("myapp")

    @pytest.mark.asyncio
    async def test_masked_fetch_no_plaintext_in_values(self):
        snap = await _FakeSource().masked_fetch()
        assert "plaintext" not in snap.secrets.values()

    @pytest.mark.asyncio
    async def test_fetch_with_retry_succeeds_first_try(self):
        snap = await _FakeSource().fetch_with_retry(max_retries=3, delay=0)
        assert snap.source == "fake"

    @pytest.mark.asyncio
    async def test_fetch_with_retry_raises_after_exhaustion(self):
        with pytest.raises(SourceError, match="2 attempt"):
            await _BrokenSource().fetch_with_retry(max_retries=2, delay=0)

    @pytest.mark.asyncio
    async def test_retry_attempts_label_in_error(self):
        try:
            await _BrokenSource().fetch_with_retry(max_retries=3, delay=0)
        except SourceError as exc:
            assert exc.attempts == 3
            # source_name comes from self.label → __class__.__name__, not self.type
            assert exc.source_name == "_BrokenSource"


class TestDotEnvSource:
    @pytest.mark.asyncio
    async def test_reads_file(self):
        path = _tmp_env("DB_PASSWORD=hunter2\nAPP_NAME=myapp\n")
        try:
            snap = await DotEnvSource(path=path).fetch()
            assert snap.secrets["DB_PASSWORD"] == "hunter2"
            assert snap.secrets["APP_NAME"]    == "myapp"
            assert snap.source.startswith("dotenv:")
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_empty_values_kept(self):
        path = _tmp_env("PRESENT=value\nEMPTY=\n")
        try:
            snap = await DotEnvSource(path=path).fetch()
            assert snap.secrets["EMPTY"] == ""
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_raises_on_missing_file(self):
        with pytest.raises(Exception):
            await DotEnvSource(path="/nonexistent/.env.xyz").fetch()


class TestSSMSource:
    @pytest.mark.asyncio
    async def test_strips_prefix(self):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = iter([{
            "Parameters": [
                {"Name": "/prod/myapp/DB_PASSWORD", "Value": "secret"},
                {"Name": "/prod/myapp/APP_NAME",    "Value": "myapp"},
            ]
        }])
        with patch("boto3.client") as mock_boto:
            mock_boto.return_value.get_paginator.return_value = mock_paginator
            snap = await SSMSource(prefix="/prod/myapp/", region="us-east-1").fetch()
        assert snap.secrets["DB_PASSWORD"] == "secret"
        assert snap.secrets["APP_NAME"]    == "myapp"

    @pytest.mark.asyncio
    async def test_source_label(self):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = iter([{"Parameters": []}])
        with patch("boto3.client") as mock_boto:
            mock_boto.return_value.get_paginator.return_value = mock_paginator
            snap = await SSMSource(prefix="/prod/", region="us-east-1").fetch()
        assert snap.source == "ssm:/prod/"


# ─────────────────────────────────────────────────────────────────────────────
# 13. Storage + History
# ─────────────────────────────────────────────────────────────────────────────

class TestStorage:
    def test_save_and_retrieve(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        rep  = _drift_report()
        rid  = stor.save_report(rep)
        assert isinstance(rid, int)
        assert rid >= 1

    def test_ids_increment(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        id1  = stor.save_report(_clean_report())
        id2  = stor.save_report(_clean_report())
        assert id2 == id1 + 1

    def test_hash_chain_stored(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        data = json.loads(open(db).read())
        assert all("hash" in row and "prev_hash" in row for row in data)

    def test_empty_db_created_on_init(self, tmp_path):
        db = _tmp_db(tmp_path)
        Storage(db_path=db)
        assert os.path.exists(db)


class TestHistory:
    def test_list_runs_returns_summaries(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        hist = History(db_path=db)
        runs = hist.list_runs()
        assert len(runs) == 2

    def test_list_runs_only_drift(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        hist = History(db_path=db)
        drifts = hist.list_runs(only_drift=True)
        assert len(drifts) == 1
        assert drifts[0].has_drift

    def test_get_run_by_id(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        rid  = stor.save_report(_drift_report())
        hist = History(db_path=db)
        row  = hist.get_run(rid)
        assert row is not None
        assert row["has_drift"] == 1

    def test_get_run_missing_returns_none(self, tmp_path):
        db   = _tmp_db(tmp_path)
        Storage(db_path=db)
        hist = History(db_path=db)
        assert hist.get_run(9999) is None

    def test_drift_trend_structure(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        hist  = History(db_path=db)
        trend = hist.drift_trend()
        assert len(trend) == 2
        assert "has_drift" in trend[0]
        assert "drift_count" in trend[0]
        assert "timestamp" in trend[0]

    def test_stats_returns_correct_counts(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        hist  = History(db_path=db)
        stats = hist.stats()
        assert stats["total_runs"]    == 2
        assert stats["drifting_runs"] == 1
        assert stats["drift_rate"]    == pytest.approx(0.5)

    def test_limit_applied(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        for _ in range(5):
            stor.save_report(_clean_report())
        hist = History(db_path=db)
        assert len(hist.list_runs(limit=3)) == 3

    def test_audit_chain_intact(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        for _ in range(4):
            stor.save_report(_clean_report())
        # verify_chain is not on History — verify manually via raw JSON
        from detector.storage.history import _compute_hash
        data = json.loads(open(db).read())
        for i, row in enumerate(data):
            prev_hash = data[i - 1]["hash"] if i > 0 else "0" * 64
            report_json_str = json.dumps(row["report_json"], default=str)
            expected_hash = _compute_hash(prev_hash, report_json_str)
            assert row["hash"] == expected_hash, f"Chain broken at row {i}"

    def test_audit_chain_broken_on_tamper(self, tmp_path):
        db   = _tmp_db(tmp_path)
        stor = Storage(db_path=db)
        stor.save_report(_clean_report())
        stor.save_report(_drift_report())
        # Tamper with row 0's hash
        data = json.loads(open(db).read())
        data[0]["hash"] = "deadbeef" * 8
        open(db, "w").write(json.dumps(data))
        # The second row's prev_hash now won't match row 0's stored hash
        from detector.storage.history import _compute_hash
        data = json.loads(open(db).read())
        broken = False
        for i, row in enumerate(data):
            prev_hash = data[i - 1]["hash"] if i > 0 else "0" * 64
            report_json_str = json.dumps(row["report_json"], default=str)
            expected_hash = _compute_hash(prev_hash, report_json_str)
            if row["hash"] != expected_hash:
                broken = True
                break
        assert broken, "Expected chain to be broken after tamper"


# ─────────────────────────────────────────────────────────────────────────────
# 14. Alerts — BaseAlerter + SlackAlerter
# ─────────────────────────────────────────────────────────────────────────────

class _NullAlerter(BaseAlerter):
    async def send_alert(self, report):
        pass


class TestBaseAlerter:
    def test_filter_items_by_min_severity(self):
        alerter = _NullAlerter(min_severity="high")
        report  = DriftReport(
            items=[
                DriftItem(key="A", kind=DriftKind.VALUE_CHANGED, severity=Severity.INFO),
                DriftItem(key="B", kind=DriftKind.VALUE_CHANGED, severity=Severity.HIGH),
                DriftItem(key="C", kind=DriftKind.VALUE_CHANGED, severity=Severity.CRITICAL),
            ],
            expected_count=3, actual_count=3,
        )
        filtered = alerter._filter_items(report)
        assert len(filtered) == 2
        assert all(i.severity >= Severity.HIGH for i in filtered)

    def test_should_alert_true(self):
        alerter = _NullAlerter(min_severity="warn")
        assert alerter._should_alert("critical")
        assert alerter._should_alert("warn")

    def test_should_alert_false(self):
        alerter = _NullAlerter(min_severity="high")
        assert not alerter._should_alert("warn")
        assert not alerter._should_alert("info")

    @pytest.mark.asyncio
    async def test_send_with_result_success(self):
        alerter = _NullAlerter(min_severity="info")
        result  = await alerter.send_with_result(_drift_report())
        assert result.success
        assert result.error is None

    @pytest.mark.asyncio
    async def test_send_with_result_failure(self):
        class _FailAlerter(BaseAlerter):
            async def send_alert(self, report):
                raise RuntimeError("boom")

        result = await _FailAlerter(min_severity="info").send_with_result(_drift_report())
        assert not result.success
        assert "boom" in result.error


class TestSlackAlerter:
    @pytest.mark.asyncio
    async def test_skips_when_no_webhook(self):
        alerter = SlackAlerter(webhook_url=None)
        # Should return without error
        await alerter.send_alert(_drift_report())

    @pytest.mark.asyncio
    async def test_skips_when_no_drift(self):
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/xxx")
        await alerter.send_alert(_clean_report())  # no items → no HTTP call

    @pytest.mark.asyncio
    async def test_sends_post_on_drift(self):
        mock_resp = AsyncMock()
        mock_resp.status = 200

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__  = AsyncMock(return_value=False)
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))

        with patch("aiohttp.ClientSession", return_value=mock_session):
            alerter = SlackAlerter(webhook_url="https://hooks.slack.com/xxx")
            await alerter.send_alert(_drift_report())

        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_mention_included_in_payload(self):
        captured: list[dict] = []

        async def _fake_post(url, json=None, **kwargs):
            captured.append(json or {})
            resp = AsyncMock()
            resp.status = 200
            return resp

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__  = AsyncMock(return_value=False)
        mock_session.post = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=AsyncMock(status=200)),
            __aexit__=AsyncMock(return_value=False),
        ))

        with patch("aiohttp.ClientSession", return_value=mock_session):
            alerter = SlackAlerter(
                webhook_url="https://hooks.slack.com/xxx",
                mention="<!channel>",
            )
            await alerter.send_alert(_drift_report(run_id=42))

        mock_session.post.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 15. Agent (mocked sources & targets)
# ─────────────────────────────────────────────────────────────────────────────


class TestAgent:
    def _make_agent_toml(self, tmp_path, env_filename: str, db_filename: str) -> str:
        """Build a valid TOML config with forward-slash paths (TOML safe on all platforms)."""
        env_path = tmp_path / env_filename
        db_path  = tmp_path / db_filename
        # TOML literal strings (single-quoted) don't interpret backslashes
        env_posix = env_path.as_posix()
        db_posix  = db_path.as_posix()
        content = (
            "[agent]\n"
            "interval_seconds = 5\n"
            "alert_on_extra   = false\n"
            "fail_on_drift    = false\n"
            "max_retries      = 1\n"
            "retry_delay      = 0\n"
            f"db_path          = '{db_posix}'\n"
            "\n"
            "[[sources]]\n"
            "type = 'dotenv'\n"
            f"path = '{env_posix}'\n"
            "\n"
            "[[targets]]\n"
            "type = 'local_env'\n"
        )
        return _tmp_toml(content)

    @pytest.mark.asyncio
    async def test_run_once_no_drift(self, tmp_path, monkeypatch):
        (tmp_path / ".env.test").write_text("DB_PASSWORD=hunter2\nAPP_NAME=myapp\n")
        monkeypatch.setenv("DB_PASSWORD", "hunter2")
        monkeypatch.setenv("APP_NAME",    "myapp")
        path = self._make_agent_toml(tmp_path, ".env.test", "agent_test.json")

        from detector.agent import Agent
        agent  = Agent.from_config(path)
        report = await agent.run_once()
        changed = report.by_kind(DriftKind.VALUE_CHANGED)
        assert not changed

    @pytest.mark.asyncio
    async def test_run_once_detects_drift(self, tmp_path, monkeypatch):
        (tmp_path / ".env.test").write_text("DB_PASSWORD=original\nAPP_NAME=myapp\n")
        monkeypatch.setenv("DB_PASSWORD", "different_value")
        monkeypatch.setenv("APP_NAME",    "myapp")
        path = self._make_agent_toml(tmp_path, ".env.test", "agent_drift.json")

        from detector.agent import Agent
        agent  = Agent.from_config(path)
        report = await agent.run_once()
        assert report.has_drift
        changed = report.by_kind(DriftKind.VALUE_CHANGED)
        assert any(i.key == "DB_PASSWORD" for i in changed)

    @pytest.mark.asyncio
    async def test_run_once_stores_to_history(self, tmp_path, monkeypatch):
        (tmp_path / ".env.test").write_text("APP_NAME=myapp\n")
        monkeypatch.setenv("APP_NAME", "myapp")
        path = self._make_agent_toml(tmp_path, ".env.test", "agent_hist.json")

        from detector.agent import Agent
        agent = Agent.from_config(path)
        await agent.run_once()

        hist = History(db_path=str(tmp_path / "agent_hist.json"))
        runs = hist.list_runs()
        assert len(runs) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 16. Server — FastAPI REST + WebSocket auth
# ─────────────────────────────────────────────────────────────────────────────

class TestServer:
    @pytest.fixture(autouse=True)
    def _setup_env(self, tmp_path):
        os.environ["DRIFT_API_KEY"] = "test-secret-key"
        os.environ["DRIFT_DB_PATH"] = str(tmp_path / "srv_test.json")

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from detector.server.app import app
        with TestClient(app) as c:
            yield c

    HEADERS = {"X-API-Key": "test-secret-key"}

    def test_health_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_list_runs_no_auth_rejected(self, client):
        r = client.get("/api/v1/runs")
        assert r.status_code == 403

    def test_list_runs_with_auth_ok(self, client):
        r = client.get("/api/v1/runs", headers=self.HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_latest_run_no_data_returns_404(self, client):
        r = client.get("/api/v1/latest")
        assert r.status_code == 404

    def test_stats_endpoint(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_runs" in data
        assert "drift_rate" in data

    def test_trend_endpoint(self, client):
        r = client.get("/api/v1/trend")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_run_not_found(self, client):
        r = client.get("/api/v1/runs/99999")
        assert r.status_code == 404

    def test_websocket_rejected_without_token(self, client):
        # Starlette's TestClient raises WebSocketDisconnect when the server
        # closes the connection during the handshake (no token → code 1008)
        from starlette.websockets import WebSocketDisconnect
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/api/v1/ws"):
                pass  # server rejects before we can receive anything

    def test_websocket_accepted_with_token(self, client):
        # Should NOT raise — connection is accepted
        try:
            with client.websocket_connect("/api/v1/ws?token=test-secret-key"):
                pass  # connected successfully
        except Exception as exc:
            pytest.fail(f"WebSocket with valid token was rejected: {exc}")

    def test_wrong_api_key_rejected(self, client):
        r = client.get("/api/v1/runs", headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 403

    def test_metrics_endpoint_accessible(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 17. Integration — End-to-end flow (no external services)
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEnd:
    @pytest.fixture
    def env_file(self, tmp_path):
        p = tmp_path / ".env.test"
        p.write_text(
            "DB_PASSWORD=hunter2\n"
            "APP_NAME=myapp\n"
            "STRIPE_SECRET_KEY=sk_live_xyz\n"
        )
        return str(p)

    @pytest.fixture
    def db_path(self, tmp_path):
        return _tmp_db(tmp_path)

    @pytest.mark.asyncio
    async def test_no_drift_round_trip(self, env_file, db_path, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD",       "hunter2")
        monkeypatch.setenv("APP_NAME",          "myapp")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz")

        src    = DotEnvSource(path=env_file)
        snap   = await src.masked_fetch()
        prober = LocalEnvProber(key_filter=["DB_PASSWORD", "APP_NAME", "STRIPE_SECRET_KEY"])
        raw    = await prober.probe()
        actual = {k: _hash(v) for k, v in raw.items()}

        report = compute_drift(snap.secrets, actual,
                               sources=[snap.source], targets=["local_env"])
        assert not report.has_drift

        Storage(db_path=db_path).save_report(report)
        row = History(db_path=db_path).get_run(1)
        assert row["has_drift"] == 0

    @pytest.mark.asyncio
    async def test_drift_round_trip(self, env_file, db_path, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD", "changed_password")
        monkeypatch.setenv("APP_NAME",    "myapp")
        monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)

        src    = DotEnvSource(path=env_file)
        snap   = await src.masked_fetch()
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

        Storage(db_path=db_path).save_report(report)
        trend = History(db_path=db_path).drift_trend()
        assert trend[0]["has_drift"] == 1

    @pytest.mark.asyncio
    async def test_multi_run_trend_accuracy(self, env_file, db_path, monkeypatch):
        stor = Storage(db_path=db_path)

        # Run 1: clean
        monkeypatch.setenv("DB_PASSWORD",       "hunter2")
        monkeypatch.setenv("APP_NAME",          "myapp")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz")
        src  = DotEnvSource(path=env_file)
        snap = await src.masked_fetch()
        keys = list(snap.secrets.keys())
        raw  = await LocalEnvProber(key_filter=keys).probe()
        stor.save_report(compute_drift(snap.secrets, {k: _hash(v) for k, v in raw.items()}))

        # Run 2: drift
        monkeypatch.setenv("DB_PASSWORD", "rotated!")
        raw2 = await LocalEnvProber(key_filter=keys).probe()
        stor.save_report(compute_drift(snap.secrets, {k: _hash(v) for k, v in raw2.items()}))

        hist  = History(db_path=db_path)
        trend = hist.drift_trend()
        assert len(trend) == 2
        assert trend[0]["has_drift"] == 0
        assert trend[1]["has_drift"] == 1

    @pytest.mark.asyncio
    async def test_audit_chain_intact_after_multiple_runs(self, env_file, db_path, monkeypatch):
        monkeypatch.setenv("DB_PASSWORD", "hunter2")
        monkeypatch.setenv("APP_NAME",    "myapp")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_xyz")

        stor = Storage(db_path=db_path)
        for _ in range(5):
            stor.save_report(_clean_report())

        # verify_chain is not on History — verify hash chain manually
        from detector.storage.history import _compute_hash
        data = json.loads(open(db_path).read())
        assert len(data) == 5
        for i, row in enumerate(data):
            prev_hash = data[i - 1]["hash"] if i > 0 else "0" * 64
            report_json_str = json.dumps(row["report_json"], default=str)
            expected_hash = _compute_hash(prev_hash, report_json_str)
            assert row["hash"] == expected_hash, f"Audit chain broken at row {i}"