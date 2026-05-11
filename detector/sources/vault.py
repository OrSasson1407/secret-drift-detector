import asyncio
import os
from datetime import datetime, timezone

import hvac

from detector.sources import BaseSource, SecretSnapshot


class VaultSource(BaseSource):
    type = "vault"

    def __init__(self, addr: str, path: str, token: str | None = None):
        self.addr  = addr
        self.path  = path
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.client = hvac.Client(url=self.addr, token=self.token)

    def _fetch_sync(self) -> dict[str, str]:
        parts       = self.path.split("/", 1)
        mount_point = parts[0]
        secret_path = parts[1] if len(parts) > 1 else ""
        response = self.client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=secret_path,
            raise_on_deleted_version=True,
        )
        raw = response["data"]["data"]
        # Vault values can be non-string; coerce all to str
        return {k: str(v) for k, v in raw.items()}

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"vault:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
        )
