from __future__ import annotations

import asyncio
import os
from typing import Optional

try:
    import hvac
    _HVAC_AVAILABLE = True
except ImportError:
    _HVAC_AVAILABLE = False

from . import BaseSource, SecretSnapshot


class VaultSource(BaseSource):
    def __init__(
        self,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        path: str = "secret/data/app",
        mount: str = "secret",
    ) -> None:
        self.addr  = addr  or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.environ.get("VAULT_TOKEN", "")
        self.path  = path
        self.mount = mount
        self.label = f"vault:{path}"

    def _fetch_sync(self) -> dict[str, str]:
        if not _HVAC_AVAILABLE:
            raise RuntimeError("hvac is not installed. Run: pip install hvac")

        client = hvac.Client(url=self.addr, token=self.token)
        if not client.is_authenticated():
            raise PermissionError(f"Vault authentication failed at {self.addr}")

        # Support both KV v1 and v2
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=self.path, mount_point=self.mount
            )
            data: dict = response["data"]["data"]
        except Exception:
            response = client.secrets.kv.v1.read_secret(
                path=self.path, mount_point=self.mount
            )
            data = response["data"]

        return {k: str(v) for k, v in data.items()}

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(source=self.label, secrets=secrets)
