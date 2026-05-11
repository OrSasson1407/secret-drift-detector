from detector.diff.models import DriftReport, DriftItem, DriftKind
from detector.diff.scorer import score_severity


def compute_drift(
    expected: dict[str, str],
    actual:   dict[str, str],
    sources:  list[str] | None = None,
    targets:  list[str] | None = None,
) -> DriftReport:
    """
    Compare expected (hashed) secrets against actual (hashed) runtime env.

    Both dicts must contain SHA-256 hex digests so no plaintext is held
    in memory during comparison.

    Returns a DriftReport with every discrepancy classified and scored.
    """
    items: list[DriftItem] = []

    # Keys present in expected but absent from runtime
    for key in sorted(expected.keys() - actual.keys()):
        kind = DriftKind.MISSING_IN_RUNTIME
        items.append(DriftItem(
            key=key,
            kind=kind,
            severity=score_severity(key, kind),
            detail="present in source(s) but absent from runtime env",
        ))

    # Keys present in runtime but absent from expected sources
    for key in sorted(actual.keys() - expected.keys()):
        kind = DriftKind.EXTRA_IN_RUNTIME
        items.append(DriftItem(
            key=key,
            kind=kind,
            severity=score_severity(key, kind),
            detail="found in runtime env but not declared in any source",
        ))

    # Keys present on both sides — compare hashes
    for key in sorted(expected.keys() & actual.keys()):
        if expected[key] != actual[key]:
            kind = DriftKind.VALUE_CHANGED
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail="hash mismatch — value differs between source and runtime",
            ))

    return DriftReport(
        items=items,
        expected_count=len(expected),
        actual_count=len(actual),
        sources=sources or [],
        targets=targets or [],
    )
