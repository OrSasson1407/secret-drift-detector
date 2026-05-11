import os
import pytest
import tempfile
from detector.config import DetectorConfig, _resolve_env


# ---------------------------------------------------------------------------
# _resolve_env
# ---------------------------------------------------------------------------

def test_resolve_env_passthrough():
    assert _resolve_env("plain_value") == "plain_value"


def test_resolve_env_reads_var(monkeypatch):
    monkeypatch.setenv("MY_SECRET_TOKEN", "tok123")
    assert _resolve_env("env:MY_SECRET_TOKEN") == "tok123"


def test_resolve_env_missing_var(monkeypatch):
    monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
    assert _resolve_env("env:NONEXISTENT_VAR") is None


def test_resolve_env_none():
    assert _resolve_env(None) is None


# ---------------------------------------------------------------------------
# DetectorConfig.load_from_file
# ---------------------------------------------------------------------------

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


def _write_toml(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_load_minimal():
    path = _write_toml(_MINIMAL_TOML)
    cfg  = DetectorConfig.load_from_file(path)
    assert cfg.agent.interval_seconds == 30
    assert len(cfg.sources) == 1
    assert cfg.sources[0].type == "dotenv"
    assert len(cfg.targets) == 1


def test_load_full(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN",    "s.abc")
    monkeypatch.setenv("DOPPLER_TOKEN",  "dp.xyz")
    monkeypatch.setenv("SLACK_WEBHOOK",  "https://hooks.slack.com/xxx")
    monkeypatch.setenv("PD_KEY",         "pd_key_123")
    path = _write_toml(_FULL_TOML)
    cfg  = DetectorConfig.load_from_file(path)

    assert cfg.agent.max_retries == 5
    assert cfg.sources[0].token == "s.abc"      # env: resolved
    assert cfg.alerts.slack.webhook_url == "https://hooks.slack.com/xxx"
    assert cfg.alerts.pagerduty.integration_key == "pd_key_123"
    assert cfg.alerts.webhook.enabled is True


def test_doppler_config_key_normalised(monkeypatch):
    """TOML key 'config' should be normalised to 'config_env'."""
    toml = _FULL_TOML  # already uses config_env
    path = _write_toml(toml)
    cfg  = DetectorConfig.load_from_file(path)
    assert cfg.sources[1].config_env == "production"
