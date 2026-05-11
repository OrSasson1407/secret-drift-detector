from detector.diff.scorer import score_severity
from detector.diff.models import Severity

def test_score_severity_patterns():
    assert score_severity("DATABASE_PASSWORD") == Severity.CRITICAL
    assert score_severity("STRIPE_SECRET") == Severity.CRITICAL
    assert score_severity("AUTH_TOKEN") == Severity.HIGH
    assert score_severity("REDIS_URL") == Severity.WARN
    assert score_severity("APP_NAME") == Severity.INFO
