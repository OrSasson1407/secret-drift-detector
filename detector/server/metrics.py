from prometheus_client import Counter, Gauge

DRIFT_CHECK_COUNT = Counter('detector_checks_total', 'Total number of drift checks performed')
DRIFT_DETECTED_COUNT = Counter('detector_drift_detected_total', 'Total number of checks where drift was found')
ACTIVE_DRIFT_ITEMS = Gauge('detector_active_drift_items', 'Current number of drifted secrets')
EXPECTED_SECRETS = Gauge('detector_expected_secrets', 'Number of expected secrets tracked')
RUNTIME_SECRETS = Gauge('detector_runtime_secrets', 'Number of secrets found in runtime')
