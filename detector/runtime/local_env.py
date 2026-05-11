import os
from detector.runtime import BaseProber


class LocalEnvProber(BaseProber):
    type = "local_env"

    def __init__(self, key_filter: list[str] | None = None):
        """
        key_filter: optional list of key prefixes to include.
        If None, all environment variables are returned.
        """
        self.key_filter = key_filter

    async def probe(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.key_filter:
            env = {k: v for k, v in env.items()
                   if any(k.startswith(p) for p in self.key_filter)}
        return env
