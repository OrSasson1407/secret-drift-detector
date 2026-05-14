import math
import re
from detector.diff.models import Severity, DriftKind

_DEFAULT_RULES: list[tuple[re.Pattern, Severity, Severity]] = [
    (
        re.compile(
            r"PASSWORD|PASSWD|SECRET|PRIVATE_KEY|PRIV_KEY|"
            r"API_KEY|ENCRYPTION_KEY|RSA_KEY|PGP|HMAC",
            re.I,
        ),
        Severity.CRITICAL,
        Severity.HIGH,
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

_STALE_MIN = Severity.HIGH

# Known trivially weak values (lower-cased for comparison)
_WEAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(password|passwd|secret|changeme|1234|admin|test|demo|example|placeholder|todo|fixme|xxx+|null|none|empty|blank|default)$", re.I),
    re.compile(r"^(.)\1{4,}$"),   # 5+ repeated chars: aaaaa, 00000
    re.compile(r"^[0-9]{1,6}$"),  # all-numeric short values
]

# Minimum Shannon entropy (bits per character) to not flag as weak
_ENTROPY_THRESHOLD = 2.5
# Minimum value length — very short values skipped (e.g. "1", "on")
_MIN_VALUE_LENGTH = 6


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character for *value*."""
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_weak_value(value: str) -> tuple[bool, float]:
    """
    Return (is_weak, entropy_score).

    A value is considered weak if it is too short, matches a known-bad
    pattern, or has Shannon entropy below the threshold.
    """
    if len(value) < _MIN_VALUE_LENGTH:
        return False, shannon_entropy(value)   # too short to score meaningfully

    entropy = shannon_entropy(value)

    for pat in _WEAK_PATTERNS:
        if pat.match(value):
            return True, entropy

    if entropy < _ENTROPY_THRESHOLD:
        return True, entropy

    return False, entropy


def score_severity(
    key: str,
    kind: DriftKind | None = None,
    *,
    custom_rules: list[tuple[re.Pattern, Severity, Severity]] | None = None,
) -> Severity:
    """Assign a severity level to a drifted key."""
    if kind == DriftKind.ORPHANED:
        return Severity.CRITICAL

    rules = custom_rules if custom_rules is not None else _DEFAULT_RULES

    for pattern, base_severity, extra_cap in rules:
        if pattern.search(key):
            if kind == DriftKind.EXTRA_IN_RUNTIME:
                return extra_cap
            if kind == DriftKind.STALE_SECRET:
                return max(base_severity, _STALE_MIN, key=lambda s: s.rank)
            if kind in (DriftKind.RENAMED, DriftKind.WEAK_VALUE):
                return base_severity
            return base_severity

    if kind == DriftKind.STALE_SECRET:
        return _STALE_MIN
    if kind == DriftKind.WEAK_VALUE:
        return Severity.WARN
    return Severity.INFO


def remediation_hint(key: str, kind: DriftKind, renamed_from: str | None = None) -> str:
    """Return a short human-readable action hint for a drift item."""
    if kind == DriftKind.MISSING_IN_RUNTIME:
        return f"Restart the target process/container so it picks up '{key}' from the source."
    if kind == DriftKind.EXTRA_IN_RUNTIME:
        return f"'{key}' is not in any configured source — audit and remove or add it to a source."
    if kind == DriftKind.VALUE_CHANGED:
        return f"Rotate or redeploy to sync '{key}' between source and runtime."
    if kind == DriftKind.STALE_SECRET:
        return f"Rotate '{key}' — it has exceeded its maximum age policy."
    if kind == DriftKind.RENAMED:
        old = renamed_from or "unknown"
        return (
            f"'{old}' in source appears renamed to '{key}' in runtime. "
            f"Update your source or runtime config so both use the same name."
        )
    if kind == DriftKind.ORPHANED:
        return (
            f"'{key}' exists in runtime but is absent from ALL configured sources. "
            f"Potential orphaned credential — rotate and remove immediately."
        )
    if kind == DriftKind.WEAK_VALUE:
        return f"The value of '{key}' has low entropy. Replace it with a strong randomly generated secret."
    return ""


# ── Levenshtein / rename helpers ────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _similarity(a: str, b: str) -> float:
    max_len = max(len(a), len(b), 1)
    return 1.0 - _levenshtein(a, b) / max_len


def find_likely_renames(
    missing_keys: set[str],
    extra_keys: set[str],
    threshold: float = 0.72,
) -> list[tuple[str, str, float]]:
    """Match likely-renamed keys. Returns (old, new, score) tuples."""
    candidates: list[tuple[str, str, float]] = []
    for old in missing_keys:
        for new in extra_keys:
            score = _similarity(old, new)
            if score >= threshold:
                candidates.append((old, new, score))

    candidates.sort(key=lambda t: -t[2])
    used_old: set[str] = set()
    used_new: set[str] = set()
    result: list[tuple[str, str, float]] = []
    for old, new, score in candidates:
        if old not in used_old and new not in used_new:
            result.append((old, new, score))
            used_old.add(old)
            used_new.add(new)
    return result
