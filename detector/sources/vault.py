import hvac
import asyncio
import os
from datetime import datetime, timezone
from detector.sources import BaseSource, SecretSnapshot

class VaultSource(BaseSource):
    def __init__(self, addr: str, path: str, token: str = None):
        self.addr = addr
        self.path = path
        # Fallback to environment variable if token isn't explicitly passed
        self.token = token or os.environ.get('VAULT_TOKEN')
        self.client = hvac.Client(url=self.addr, token=self.token)

    def _fetch_sync(self):
        # Assuming KV v2 engine which is standard for modern Vault deployments
        # Mount point is assumed to be the first part of the path (e.g., 'secret')
        parts = self.path.split('/', 1)
        mount_point = parts[0]
        secret_path = parts[1] if len(parts) > 1 else ""
        
        response = self.client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point, 
            path=secret_path
        )
        return response['data']['data']

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"vault:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets
        )
