from detector.diff.models import DriftReport, DriftItem, DriftKind, Severity
from detector.diff.scorer import (
    score_severity,
    remediation_hint,
    find_likely_renames,
    is_weak_value,
)


def compute_drift(
    expected:          dict[str, str],
    actual:            dict[str, str],
    sources:           list[str] | None = None,
    targets:           list[str] | None = None,
    stale_keys:        set[str]  | None = None,
    source_map:        dict[str, str] | None = None,
    all_source_keys:   set[str]  | None = None,
    rename_threshold:  float = 0.72,
    actual_plaintext:  dict[str, str] | None = None,
    enable_entropy:    bool = True,
) -> DriftReport:
    """
    Compare expected (SHA-256 hashed) secrets against actual (SHA-256 hashed)
    runtime env. Returns a fully annotated DriftReport.

    New capabilities vs original:
      - RENAMED: fuzzy pre-pass surfaces likely-renamed keys.
      - ORPHANED: runtime extras absent from ALL sources → CRITICAL.
      - WEAK_VALUE: Shannon entropy scoring on actual plaintext values.

    Args:
        expected:         {key: sha256_hex} from authoritative source(s).
        actual:           {key: sha256_hex} from runtime probe(s).
        sources:          Human-readable source labels.
        targets:          Human-readable target labels.
        stale_keys:       Keys past their rotation deadline.
        source_map:       {key: source_label} for attribution.
        all_source_keys:  Union of ALL source keys for orphan detection.
        rename_threshold: Similarity threshold for rename detection (0-1).
        actual_plaintext: {key: plaintext_value} for entropy scoring. When
                          None, entropy checks are skipped even if enabled.
        enable_entropy:   Master switch for WEAK_VALUE checks.
    """
    items: list[DriftItem] = []
    stale   = stale_keys or set()
    smap    = source_map or {}
    all_src = all_source_keys if all_source_keys is not None else set(expected.keys())
    pt      = actual_plaintext or {}

    def _origin(key: str) -> str:
        src = smap.get(key)
        return f" (from {src})" if src else ""

    missing_keys = expected.keys() - actual.keys()
    extra_keys   = actual.keys()   - expected.keys()

    # ── Rename pre-pass ────────────────────────────────────
    renames    = find_likely_renames(set(missing_keys), set(extra_keys), threshold=rename_threshold)
    rename_old = {old for old, _, _ in renames}
    rename_new = {new for _, new, _ in renames}

    for old_key, new_key, score in renames:
        kind = DriftKind.RENAMED
        items.append(DriftItem(
            key=new_key,
            kind=kind,
            severity=score_severity(old_key, kind),
            detail=(
                f"'{old_key}' in source{_origin(old_key)} appears renamed to "
                f"'{new_key}' in runtime (similarity {score:.0%})"
            ),
            remediation_hint=remediation_hint(new_key, kind, renamed_from=old_key),
            renamed_from=old_key,
        ))

    # ── Missing in runtime ─────────────────────────────────
    for key in sorted(missing_keys - rename_old):
        kind = DriftKind.MISSING_IN_RUNTIME
        items.append(DriftItem(
            key=key,
            kind=kind,
            severity=score_severity(key, kind),
            detail=f"present in source(s){_origin(key)} but absent from runtime env",
            remediation_hint=remediation_hint(key, kind),
        ))

    # ── Extra in runtime: ORPHANED vs EXTRA ───────────────
    for key in sorted(extra_keys - rename_new):
        if key not in all_src:
            kind = DriftKind.ORPHANED
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=Severity.CRITICAL,
                detail="found in runtime but absent from ALL configured sources — potential orphaned credential",
                remediation_hint=remediation_hint(key, kind),
            ))
        else:
            kind = DriftKind.EXTRA_IN_RUNTIME
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail="found in runtime env but not declared in any source",
                remediation_hint=remediation_hint(key, kind),
            ))

    # ── Value changed ──────────────────────────────────────
    for key in sorted(expected.keys() & actual.keys()):
        if expected[key] != actual[key]:
            kind = DriftKind.VALUE_CHANGED
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail=f"hash mismatch — value differs between source{_origin(key)} and runtime",
                remediation_hint=remediation_hint(key, kind),
            ))

    # ── Stale secrets ──────────────────────────────────────
    for key in sorted(stale):
        if key in expected or key in actual:
            kind = DriftKind.STALE_SECRET
            items.append(DriftItem(
                key=key,
                kind=kind,
                severity=score_severity(key, kind),
                detail=f"secret{_origin(key)} exceeds maximum rotation age",
                remediation_hint=remediation_hint(key, kind),
            ))

    # ── Entropy / weak-value scan ──────────────────────────
    if enable_entropy and pt:
        already_flagged = {i.key for i in items}
        for key, plaintext in sorted(pt.items()):
            if key in already_flagged:
                continue   # don't double-flag keys already drifted
            weak, entropy = is_weak_value(plaintext)
            if weak:
                kind = DriftKind.WEAK_VALUE
                items.append(DriftItem(
                    key=key,
                    kind=kind,
                    severity=score_severity(key, kind),
                    detail=f"value has low entropy ({entropy:.2f} bits/char) — may be a placeholder or weak secret",
                    remediation_hint=remediation_hint(key, kind),
                    entropy_score=round(entropy, 4),
                ))

    items.sort(key=lambda i: (-i.severity.rank, i.key))

    return DriftReport(
        items=items,
        expected_count=len(expected),
        actual_count=len(actual),
        sources=sources or [],
        targets=targets or [],
    )
