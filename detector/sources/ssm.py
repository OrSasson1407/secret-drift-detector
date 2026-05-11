import boto3
import asyncio
from datetime import datetime, timezone
from detector.sources import BaseSource, SecretSnapshot

class SSMSource(BaseSource):
    def __init__(self, prefix: str, region: str):
        self.prefix = prefix
        self.region = region
        self.client = boto3.client('ssm', region_name=region)

    def _fetch_sync(self):
        paginator = self.client.get_paginator('get_parameters_by_path')
        secrets = {}
        # Fetch all pages of parameters under the given path
        for page in paginator.paginate(Path=self.prefix, WithDecryption=True):
            for param in page['Parameters']:
                # Strip the prefix to get the clean environment variable name
                # e.g., '/production/myapp/DB_PASSWORD' -> 'DB_PASSWORD'
                key = param['Name'][len(self.prefix):].lstrip('/')
                secrets[key] = param['Value']
        return secrets

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"ssm:{self.prefix}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets
        )
