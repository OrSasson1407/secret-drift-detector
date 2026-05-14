import aiohttp
from detector.runtime import BaseProber


class HttpIntrospectProber(BaseProber):
    """
    Calls an application-exposed endpoint (e.g. /_debug/env) that returns
    environment variables as a JSON object { "KEY": "value", ... }.
    Only use this on internal, protected endpoints.
    """
    type = "http_introspect"

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: int = 10):
        self.url     = url
        self.headers = headers or {}
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def probe(self) -> dict[str, str]:
        async with aiohttp.ClientSession(headers=self.headers, timeout=self.timeout) as session:
            async with session.get(self.url) as resp:
                if resp.status != 200:
                    raise RuntimeError(
                        f"HttpIntrospectProber: {self.url} returned HTTP {resp.status}"
                    )
                data = await resp.json()

        if not isinstance(data, dict):
            raise ValueError(f"HttpIntrospectProber: expected JSON object, got {type(data)}")

        return {str(k): str(v) for k, v in data.items()}
