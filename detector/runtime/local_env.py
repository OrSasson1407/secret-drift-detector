import os
from detector.runtime import BaseProber

class LocalEnvProber(BaseProber):
    async def probe(self) -> dict[str, str]:
        # Reads the live Windows environment variables
        return dict(os.environ)
