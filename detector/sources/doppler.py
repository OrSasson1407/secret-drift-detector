import os
from datetime import datetime, timezone

import aiohttp

from detector.sources import BaseSource, SecretSnapshot, SourceError

_DOPPLER_API = "https://api.doppler.com/v3/configs/config/secrets/download"


class DopplerSource(BaseSource):
    type = "doppler"

    def __init__(
        self,
        project:    str,
        config_env: str,
        token:      str | None = None,
        key_prefix: str | None = None,
        timeout:    float = 10.0,
    ):
        self.project    = project
        self.config_env = config_env
        self.token      = token or os.environ.get("DOPPLER_TOKEN")
        self.key_prefix = key_prefix.rstrip("/") + "/" if key_prefix else None
        self.timeout    = aiohttp.ClientTimeout(total=timeout)

    @property
    def label(self) -> str:
        return f"DopplerSource(project={self.project!r}, env={self.config_env!r})"

    async def fetch(self) -> SecretSnapshot:
        if not self.token:
            raise SourceError(
                self.label,
                RuntimeError("no token provided and DOPPLER_TOKEN is not set"),
            )

        params = {
            "project": self.project,
            "config":  self.config_env,
            "format":  "json",
        }
        auth = aiohttp.BasicAuth(self.token, "")

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(_DOPPLER_API, params=params, auth=auth) as resp:
                    if resp.status == 401:
                        raise SourceError(
                            self.label,
                            PermissionError("Doppler token is invalid or revoked (HTTP 401)"),
                        )
                    if resp.status == 404:
                        raise SourceError(
                            self.label,
                            KeyError(
                                f"Doppler project '{self.project}' / "
                                f"config '{self.config_env}' not found (HTTP 404)"
                            ),
                        )
                    if resp.status != 200:
                        body = await resp.text()
                        raise SourceError(
                            self.label,
                            RuntimeError(f"Doppler API error HTTP {resp.status}: {body}"),
                        )
                    data: dict = await resp.json()

        except aiohttp.ClientError as exc:
            raise SourceError(self.label, exc) from exc

        # Doppler returns {"KEY": {"raw": "value", ...}, ...}
        secrets: dict[str, str] = {}
        for k, v in data.items():
            if not isinstance(v, dict):
                continue
            name = k
            if self.key_prefix and name.startswith(self.key_prefix):
                name = name[len(self.key_prefix):]
            secrets[name] = v.get("raw", "")

        return SecretSnapshot(
            source=f"doppler:{self.project}/{self.config_env}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
            metadata={"key_count": len(secrets)},
        )

