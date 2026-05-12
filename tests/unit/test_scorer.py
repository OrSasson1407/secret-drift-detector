import pytest
from detector.diff.scorer import score_severity
from detector.diff.models import Severity, DriftKind


# ---------------------------------------------------------------------------
# CRITICAL patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "DATABASE_PASSWORD",
    "DB_PASSWD",
    "STRIPE_SECRET_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE_KEY",
    "ENCRYPTION_KEY",
    "API_KEY",
])
def test_critical_patterns(key):
    assert score_severity(key) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# HIGH patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "AUTH_TOKEN",
    "GITHUB_TOKEN",
    "ACCESS_TOKEN",
    "TLS_CERT",
    "CLIENT_CREDENTIAL",
    
])
def test_high_patterns(key):
    assert score_severity(key) == Severity.HIGH


# ---------------------------------------------------------------------------
# WARN patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "REDIS_URL",
    "DATABASE_HOST",
    "API_ENDPOINT",
    "DB_CONNECTION",
    "SERVICE_DSN",
])
def test_warn_patterns(key):
    assert score_severity(key) == Severity.WARN


# ---------------------------------------------------------------------------
# INFO (no pattern match)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "APP_NAME",
    "LOG_LEVEL",
    
    "ENVIRONMENT",
    "REGION",
])
def test_info_patterns(key):
    assert score_severity(key) == Severity.INFO


# ---------------------------------------------------------------------------
# EXTRA_IN_RUNTIME cap
# ---------------------------------------------------------------------------

def test_extra_critical_capped_at_high():
    sev = score_severity("DATABASE_PASSWORD", kind=DriftKind.EXTRA_IN_RUNTIME)
    assert sev == Severity.HIGH


def test_extra_high_stays_high():
    sev = score_severity("AUTH_TOKEN", kind=DriftKind.EXTRA_IN_RUNTIME)
    assert sev == Severity.HIGH


def test_extra_warn_stays_warn():
    sev = score_severity("REDIS_URL", kind=DriftKind.EXTRA_IN_RUNTIME)
    assert sev == Severity.WARN


def test_missing_critical_stays_critical():
    sev = score_severity("DATABASE_PASSWORD", kind=DriftKind.MISSING_IN_RUNTIME)
    assert sev == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Case insensitivity
# ---------------------------------------------------------------------------

def test_case_insensitive():
    assert score_severity("database_password") == Severity.CRITICAL
    assert score_severity("Auth_Token") == Severity.HIGH

