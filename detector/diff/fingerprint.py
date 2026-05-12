import re
PATTERNS = {'aws_access_key': r'AKIA[0-9A-Z]{16}', 'slack_token': r'xox[baprs]-[0-9]+', 'stripe_key': r'sk_(live|test)_[0-9a-zA-Z]+'}
def identify_secret_type(val: str) -> str:
    for name, pat in PATTERNS.items():
        if re.search(pat, val): return name
    return "generic_secret"
