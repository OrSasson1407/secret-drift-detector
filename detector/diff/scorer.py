import re
from detector.diff.models import Severity, DriftKind

# ---------------------------------------------------------------------------
# Default rules — ordered highest → lowest priority, first match wins.
# Each entry: (compiled pattern, severity for MISSING/CHANGED, cap for EXTRA)
# ---------------------------------------------------------------------------
_DEFAULT_RULES: list[tuple[re.Pattern, Severity, Severity]] = [
    (
        re.compile(
            r"PASSWORD|PASSWD|SECRET|PRIVATE_KEY|PRIV_KEY|"
            r"API_KEY|ENCRYPTION_KEY|RSA_KEY|PGP|HMAC",
            re.I,
        ),
        Severity.CRITICAL,
        Severity.HIGH,      # EXTRA cap: unknown secret found in runtime
    ),
    (
        re.compile(r"TOKEN|CERT|CREDENTIAL|AUTH|SIGNING|OAUTH|JWT|MFA|TOTP", re.I),
        Severity.HIGH,
        Severity.HIGH,
    ),
    (
        re.compile(r"URL|HOST|ENDPOINT|DSN|CONNECTION|PORT|ADDR|SOCKET", re.I),
        Severity.WARN,
        Severity.WARN,
    ),
]

# Stale secrets (rotation overdue) are always at least HIGH
_STALE_MIN = Severity.HIGH


def score_severity(
    key: str,
    kind: DriftKind | None = None,
    *,
    custom_rules: list[tuple[re.Pattern, Severity, Severity]] | None = None,
) -> Severity:
    """
    Assign a severity level to a drifted key.

    Rules (first match wins):
      - CRITICAL-pattern key that is MISSING_IN_RUNTIME or VALUE_CHANGED → CRITICAL
      - EXTRA_IN_RUNTIME items are capped per rule (unknown extras are notable
        but rarely as urgent as a missing password)
      - STALE_SECRET is always at least HIGH
      - Falls back to INFO if no pattern matches

    Args:
        key:          The environment variable name being evaluated.
        kind:         DriftKind for the item (affects cap logic).
        custom_rules: Optional override rule list (same shape as _DEFAULT_RULES).
    """
    rules = custom_rules if custom_rules is not None else _DEFAULT_RULES

    for pattern, base_severity, extra_cap in rules:
        if pattern.search(key):
            if kind == DriftKind.EXTRA_IN_RUNTIME:
                return extra_cap
            if kind == DriftKind.STALE_SECRET:
                return max(base_severity, _STALE_MIN, key=lambda s: s.rank)
            return base_severity

    # No pattern matched
    if kind == DriftKind.STALE_SECRET:
        return _STALE_MIN
    return Severity.INFO


def remediation_hint(key: str, kind: DriftKind) -> str:
    """Return a short human-readable action hint for a drift item."""
    if kind == DriftKind.MISSING_IN_RUNTIME:
        return f"Restart the target process/container so it picks up '{key}' from the source."
    if kind == DriftKind.EXTRA_IN_RUNTIME:
        return f"'{key}' is not in any configured source — audit and remove or add it to a source."
    if kind == DriftKind.VALUE_CHANGED:
        return f"Rotate or redeploy to sync '{key}' between source and runtime."
    if kind == DriftKind.STALE_SECRET:
        return f"Rotate '{key}' — it has exceeded its maximum age policy."
    return ""
