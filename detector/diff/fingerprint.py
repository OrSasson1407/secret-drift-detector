import re

PATTERNS = {
    'aws_access_key': r'(?i)AKIA[0-9A-Z]{16}',
    'github_pat': r'ghp_[a-zA-Z0-9]{36}',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]+',
    'stripe_key': r'sk_(live|test)_[0-9a-zA-Z]{24}',
}

def identify_secret_type(value: str) -> str:
    "\""Analyzes a string to guess the type of secret."\""
    for name, pattern in PATTERNS.items():
        if re.search(pattern, value):
            return name
    return "generic_secret"
