from datetime import datetime, timezone

import dotenv

from detector.sources import BaseSource, SecretSnapshot


class DotEnvSource(BaseSource):
    type = "dotenv"

    def __init__(self, path: str):
        self.path = path

    async def fetch(self) -> SecretSnapshot:
        raw = dotenv.dotenv_values(self.path)
        secrets = {k: v for k, v in raw.items() if v is not None}
        return SecretSnapshot(
            source=f"dotenv:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
        )
