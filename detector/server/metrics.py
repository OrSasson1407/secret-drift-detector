from prometheus_client import Counter, Gauge

DRIFT_CHECK_COUNT    = Counter("drift_check_total",    "Total number of drift checks run")
DRIFT_DETECTED_COUNT = Counter("drift_detected_total", "Total checks that found drift")
EXPECTED_SECRETS     = Gauge("drift_expected_secrets", "Number of secrets in expected sources")
RUNTIME_SECRETS      = Gauge("drift_runtime_secrets",  "Number of secrets found in runtime")
ACTIVE_DRIFT_ITEMS   = Gauge("drift_active_items",     "Number of drift items in last check")

# --- Source Health Monitoring ---
SOURCE_FETCH_SUCCESS = Counter("drift_source_fetch_success_total", "Total successful source fetches", ["source_name"])
SOURCE_FETCH_ERROR   = Counter("drift_source_fetch_error_total", "Total failed source fetches", ["source_name"])

# --- Auto-Remediation ---
REMEDIATION_TRIGGERED = Counter("drift_remediation_triggered_total", "Total auto-remediations triggered")
