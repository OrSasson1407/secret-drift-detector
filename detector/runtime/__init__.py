from abc import ABC, abstractmethod


class BaseProber(ABC):
    type: str = "base"

    @abstractmethod
    async def probe(self) -> dict[str, str]:
        """Return live environment variables as a key→value dict."""
        ...

    @staticmethod
    def _parse_env_output(raw: str) -> dict[str, str]:
        """Parse newline-separated KEY=VALUE output (docker exec env, kubectl exec env)."""
        env: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
        return env
