import re
from detector.diff.models import Severity

def score_severity(key: str) -> Severity:
    key_upper = key.upper()
    if re.search(r'KEY|SECRET|PASSWORD', key_upper):
        return Severity.CRITICAL
    elif re.search(r'TOKEN|CERT', key_upper):
        return Severity.HIGH
    elif re.search(r'URL|HOST', key_upper):
        return Severity.WARN
    return Severity.INFO
