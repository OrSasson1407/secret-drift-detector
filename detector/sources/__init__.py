import asyncio
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pydantic import BaseModel


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecretSnapshot(BaseModel):
    source:     str
    fetched_at: datetime
    secrets:    dict[str, str]
    metadata:   dict = {}


class BaseSource(ABC):
    type: str = "base"

    @abstractmethod
    async def fetch(self) -> SecretSnapshot:
        ...

    async def masked_fetch(self) -> SecretSnapshot:
        snap = await self.fetch()
        snap.secrets = {k: _hash(v) for k, v in snap.secrets.items()}
        return snap

    async def fetch_with_retry(self, max_retries: int = 3, delay: float = 2.0) -> SecretSnapshot:
        last_exc: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                return await self.masked_fetch()
            except Exception as exc:
                last_exc = exc
                if attempt < max_retries:
                    await asyncio.sleep(delay * attempt)
        raise RuntimeError(
            f"[{self.__class__.__name__}] failed after {max_retries} attempts: {last_exc}"
        ) from last_exc
