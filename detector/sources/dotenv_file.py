import dotenv
from datetime import datetime, timezone
from detector.sources import BaseSource, SecretSnapshot

class DotEnvSource(BaseSource):
    def __init__(self, path: str):
        self.path = path

    async def fetch(self) -> SecretSnapshot:
        # dotenv_values returns a dict of the parsed file
        raw_secrets = dotenv.dotenv_values(self.path)
        
        # Filter out None values just in case there are empty declarations
        secrets = {k: v for k, v in raw_secrets.items() if v is not None}
        
        return SecretSnapshot(
            source=f"dotenv:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets
        )
