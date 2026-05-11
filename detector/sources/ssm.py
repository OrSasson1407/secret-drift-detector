from __future__ import annotations

import asyncio
import os
from typing import Optional

try:
    import boto3
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

from . import BaseSource, SecretSnapshot


class SSMSource(BaseSource):
    def __init__(
        self,
        prefix: str,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        decrypt: bool = True,
    ) -> None:
        self.prefix  = prefix if prefix.endswith("/") else prefix + "/"
        self.region  = region  or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.profile = profile or os.environ.get("AWS_PROFILE")
        self.decrypt = decrypt
        self.label   = f"ssm:{self.prefix}"

    def _fetch_sync(self) -> dict[str, str]:
        if not _BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Run: pip install boto3")

        session = boto3.Session(profile_name=self.profile, region_name=self.region)
        client  = session.client("ssm")

        secrets: dict[str, str] = {}
        paginator = client.get_paginator("get_parameters_by_path")

        for page in paginator.paginate(
            Path=self.prefix,
            Recursive=True,
            WithDecryption=self.decrypt,
        ):
            for param in page["Parameters"]:
                # Strip the prefix to get the bare key name
                key = param["Name"][len(self.prefix):]
                # Convert path separators to underscores: sub/key -> SUB_KEY
                key = key.replace("/", "_").upper()
                secrets[key] = param["Value"]

        return secrets

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(source=self.label, secrets=secrets)
