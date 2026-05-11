from __future__ import annotations

import re
from typing import List, Tuple

from .models import DriftItem, DriftKind, Severity

_RULES: List[Tuple[re.Pattern, Severity]] = [
    (re.compile(r'(PASSWORD|PASSWD|SECRET|PRIVATE_KEY|PRIV_KEY|API_KEY|ACCESS_KEY_SECRET|SECRET_KEY|SECRET_ACCESS_KEY|SIGNING_KEY|ENCRYPTION_KEY)$', re.I), Severity.CRITICAL),
    (re.compile(r'(TOKEN|CERT|CERTIFICATE|CLIENT_SECRET|OAUTH|AUTH|CREDENTIAL|CREDS)$', re.I), Severity.HIGH),
    (re.compile(r'(URL|HOST|ENDPOINT|DSN|ADDR|ADDRESS|PORT|DATABASE_URL)$', re.I),            Severity.WARN),
    (re.compile(r'^(REDIS|MONGO|POSTGRES|MYSQL|DB)_',                       re.I),            Severity.WARN),
]


def score_item(item: DriftItem) -> DriftItem:
    key = item.key.upper()
    for pattern, severity in _RULES:
        if pattern.search(key):
            return item.model_copy(update={"severity": severity})
    if item.kind == DriftKind.MISSING_IN_RUNTIME:
        return item.model_copy(update={"severity": Severity.HIGH})
    return item.model_copy(update={"severity": Severity.INFO})


def score_report_items(items: list[DriftItem]) -> list[DriftItem]:
    return [score_item(i) for i in items]
