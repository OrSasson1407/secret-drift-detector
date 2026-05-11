from prometheus_client import Counter, Gauge

DRIFT_CHECK_COUNT    = Counter("drift_check_total",    "Total number of drift checks run")
DRIFT_DETECTED_COUNT = Counter("drift_detected_total", "Total checks that found drift")
EXPECTED_SECRETS     = Gauge("drift_expected_secrets", "Number of secrets in expected sources")
RUNTIME_SECRETS      = Gauge("drift_runtime_secrets",  "Number of secrets found in runtime")
ACTIVE_DRIFT_ITEMS   = Gauge("drift_active_items",     "Number of drift items in last check")
