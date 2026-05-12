from datetime import datetime, timezone
from detector.diff.models import DriftReport, DriftItem, DriftKind
from detector.diff.scorer import score_severity, remediation_hint


def compute_drift(
    expected:       dict[str, str],
    actual:         dict[str, str],
    sources:        list[str] | None = None,
    targets:        list[str] | None = None,
    stale_keys:     set[str] | None  = None,
) -> DriftReport:
    """
    Compare expected (SHA-256 hashed) secrets against actual (SHA-256 hashed)
    runtime env.  Returns a DriftReport with every discrepancy classified,
    scored, and annotated with a remediation hint.

    Args:
        expected:   {key: sha256_hex} from authoritative source(s).
        actual:     {key: sha256_hex} from live runtime probe(s).
        sources:    Human-readable source labels (for report metadata).
        targets:    Human-readable target labels (for report metadata).
        stale_keys: Keys already known to be past their rotation deadline.
                    These produce a STALE_SECRET item in addition to any
                    VALUE_CHANGED item that may exist.
    """
    items: list[DriftItem] = []
    stale = stale_keys or set()

    # --- Keys present in expected but absent from runtime ---
    for key in sorted(expected.keys() - actual.keys()):
        kind = DriftKind.MISSING_IN_RUNTIME
        items.append(DriftItem(
            key=key,
            kind=kind,
            severity=score_severity(key, kind),
            detail="present in source(s) but absent from runtime env",
            remediation_hint=remediation_hint(key, kind),
        ))

    # --- Keys present in runtime but absent from expected sources ---
    for key in sorted(actual.keys() - expected.keys()):
        kind = DriftKind.EXTRA_IN_RUNTIME
        items.append(DriftItem(
            key=key,
            kind=kind,
            severity=score_severity(key, kind),
            detail="found in runtime env but not declared in any source",
            remediation_hint=remediation_hint(key, kind),
        ))

    # --- Keys present on both sides — compare hashes ---
    for key in sorted(expected.keys() & actual.keys()):
        if expected[key] != actual[key]:
            kind = DriftKind.VALUE_CHANGED
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail="hash mismatch — value differs between source and runtime",
                remediation_hint=remediation_hint(key, kind),
            ))

    # --- Stale-secret items (rotation deadline exceeded) ---
    for key in sorted(stale):
        # Only add if key actually exists (missing keys are already reported above)
        if key in expected or key in actual:
            kind = DriftKind.STALE_SECRET
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail="secret exceeds maximum rotation age",
                remediation_hint=remediation_hint(key, kind),
            ))

    # Sort: highest severity first, then alphabetically by key
    items.sort(key=lambda i: (-i.severity.rank, i.key))

    return DriftReport(
        items=items,
        expected_count=len(expected),
        actual_count=len(actual),
        sources=sources or [],
        targets=targets or [],
    )
