from deepdiff import DeepDiff
from detector.diff.models import DriftReport, DriftItem, DriftKind
from detector.diff.scorer import score_severity

def compute_drift(expected: dict, actual: dict) -> DriftReport:
    items: list[DriftItem] = []
    
    # Missing in runtime
    for key in expected.keys() - actual.keys():
        items.append(DriftItem(
            key=key, 
            kind=DriftKind.MISSING_IN_RUNTIME,
            severity=score_severity(key),
            detail="not in runtime env"
        ))
        
    # Extra in runtime
    for key in actual.keys() - expected.keys():
        items.append(DriftItem(
            key=key, 
            kind=DriftKind.EXTRA_IN_RUNTIME,
            severity=score_severity(key),
            detail="found in runtime but not in expected sources"
        ))
        
    # Value changed
    for key in expected.keys() & actual.keys():
        # Using string comparison. If both are passed through masked_fetch, 
        # these will be hashes. If raw, it compares plaintexts.
        if expected[key] != actual[key]:
            items.append(DriftItem(
                key=key, 
                kind=DriftKind.VALUE_CHANGED,
                severity=score_severity(key),
                detail="hash/value mismatch"
            ))
            
    return DriftReport(
        items=items,
        expected_count=len(expected),
        actual_count=len(actual)
    )
