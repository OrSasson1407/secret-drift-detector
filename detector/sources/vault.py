import asyncio
import os
from datetime import datetime, timezone

import hvac

from detector.sources import BaseSource, SecretSnapshot, SourceError


class VaultSource(BaseSource):
    type = "vault"

    def __init__(
        self,
        addr: str,
        path: str,
        token: str | None = None,
        mount_version: int = 2,
        key_prefix: str | None = None,
        timeout: float = 10.0,
    ):
        self.addr          = addr
        self.path          = path
        self.token         = token or os.environ.get("VAULT_TOKEN")
        self.mount_version = mount_version
        self.key_prefix    = key_prefix.rstrip("/") + "/" if key_prefix else None
        self.timeout       = timeout

        # Vault Enterprise namespace (optional)
        vault_ns = os.environ.get("VAULT_NAMESPACE")
        self.client = hvac.Client(
            url=self.addr,
            token=self.token,
            timeout=int(self.timeout),
            namespace=vault_ns or None,
        )

    @property
    def label(self) -> str:
        return f"VaultSource(path={self.path!r}, kv=v{self.mount_version})"

    def _fetch_sync(self) -> dict[str, str]:
        parts       = self.path.split("/", 1)
        mount_point = parts[0]
        secret_path = parts[1] if len(parts) > 1 else ""

        try:
            if self.mount_version == 1:
                response = self.client.secrets.kv.v1.read_secret(
                    mount_point=mount_point,
                    path=secret_path,
                )
                raw = response["data"]
            else:
                response = self.client.secrets.kv.v2.read_secret_version(
                    mount_point=mount_point,
                    path=secret_path,
                    raise_on_deleted_version=True,
                )
                raw = response["data"]["data"]
        except hvac.exceptions.InvalidPath as exc:
            raise SourceError(self.label, exc) from exc
        except hvac.exceptions.Forbidden as exc:
            raise SourceError(
                self.label,
                PermissionError(f"Vault token lacks read access to '{self.path}'"),
            ) from exc
        except hvac.exceptions.VaultError as exc:
            raise SourceError(self.label, exc) from exc

        secrets: dict[str, str] = {}
        for k, v in raw.items():
            # Strip configured key_prefix (e.g. "myapp/" -> "DB_PASS")
            name = k
            if self.key_prefix and name.startswith(self.key_prefix):
                name = name[len(self.key_prefix):]
            secrets[name] = str(v)
        return secrets

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"vault:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
            metadata={"mount_version": self.mount_version},
        )
