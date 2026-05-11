import asyncio
from datetime import datetime, timezone

import boto3

from detector.sources import BaseSource, SecretSnapshot


class SSMSource(BaseSource):
    type = "ssm"

    def __init__(self, prefix: str, region: str):
        self.prefix = prefix.rstrip("/") + "/"
        self.region = region
        self.client = boto3.client("ssm", region_name=region)

    def _fetch_sync(self) -> dict[str, str]:
        paginator = self.client.get_paginator("get_parameters_by_path")
        secrets: dict[str, str] = {}
        for page in paginator.paginate(Path=self.prefix, WithDecryption=True):
            for param in page["Parameters"]:
                key = param["Name"][len(self.prefix):]
                secrets[key] = param["Value"]
        return secrets

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"ssm:{self.prefix}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
        )
