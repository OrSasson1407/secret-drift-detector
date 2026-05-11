import os
from datetime import datetime, timezone

import aiohttp

from detector.sources import BaseSource, SecretSnapshot

_DOPPLER_API = "https://api.doppler.com/v3/configs/config/secrets/download"


class DopplerSource(BaseSource):
    type = "doppler"

    def __init__(self, project: str, config_env: str, token: str | None = None):
        self.project    = project
        self.config_env = config_env
        self.token      = token or os.environ.get("DOPPLER_TOKEN")

    async def fetch(self) -> SecretSnapshot:
        if not self.token:
            raise RuntimeError("DopplerSource: no token provided and DOPPLER_TOKEN not set")

        params = {"project": self.project, "config": self.config_env, "format": "json"}
        auth   = aiohttp.BasicAuth(self.token, "")

        async with aiohttp.ClientSession() as session:
            async with session.get(_DOPPLER_API, params=params, auth=auth) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(f"Doppler API error {resp.status}: {body}")
                data: dict = await resp.json()

        # Doppler returns {"KEY": {"raw": "value", ...}, ...}
        secrets = {k: v.get("raw", "") for k, v in data.items() if isinstance(v, dict)}
        return SecretSnapshot(
            source=f"doppler:{self.project}/{self.config_env}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
        )
