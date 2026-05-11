import re
from detector.diff.models import Severity, DriftKind

# Ordered from highest to lowest priority — first match wins.
_RULES: list[tuple[re.Pattern, Severity]] = [
    (re.compile(r"PASSWORD|PASSWD|SECRET|PRIVATE_KEY|PRIV_KEY|API_KEY|ENCRYPTION_KEY", re.I), Severity.CRITICAL),
    (re.compile(r"TOKEN|CERT|CREDENTIAL|AUTH|SIGNING",  re.I), Severity.HIGH),
    (re.compile(r"URL|HOST|ENDPOINT|DSN|CONNECTION",    re.I), Severity.WARN),
]


def score_severity(key: str, kind: DriftKind | None = None) -> Severity:
    """
    Assign a severity level to a drifted key.

    MISSING_IN_RUNTIME for a CRITICAL-pattern key is always CRITICAL.
    EXTRA_IN_RUNTIME items are capped at HIGH (unknown extras are notable
    but rarely as dangerous as a missing password).
    """
    for pattern, severity in _RULES:
        if pattern.search(key):
            base = severity
            break
    else:
        base = Severity.INFO

    # Extra keys in runtime are capped at HIGH — they weren't expected,
    # so we don't know their purpose yet.
    if kind == DriftKind.EXTRA_IN_RUNTIME and base == Severity.CRITICAL:
        return Severity.HIGH

    return base
