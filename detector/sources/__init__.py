import asyncio
import hashlib
import random
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pydantic import BaseModel


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SourceError(Exception):
    """Raised when a source adapter fails to fetch secrets."""

    def __init__(self, source_name: str, cause: Exception, attempts: int = 1):
        self.source_name = source_name
        self.cause       = cause
        self.attempts    = attempts
        super().__init__(
            f"[{source_name}] fetch failed after {attempts} attempt(s): {cause}"
        )


class SecretSnapshot(BaseModel):
    source:     str
    fetched_at: datetime
    secrets:    dict[str, str]
    metadata:   dict = {}


class BaseSource(ABC):
    type: str = "base"

    @property
    def label(self) -> str:
        """Human-readable identifier used in log messages."""
        return self.__class__.__name__

    @abstractmethod
    async def fetch(self) -> SecretSnapshot: ...

    async def masked_fetch(self) -> SecretSnapshot:
        snap = await self.fetch()
        snap.secrets = {k: _hash(v) for k, v in snap.secrets.items()}
        return snap

    async def fetch_with_retry(
        self, max_retries: int = 3, delay: float = 2.0
    ) -> SecretSnapshot:
        """Fetch with exponential back-off and full jitter.

        Wait formula: min(cap, base * 2^attempt) * random(0, 1)
        where cap = delay * 8 and base = delay.
        """
        last_exc: Exception | None = None
        cap = delay * 8

        for attempt in range(1, max_retries + 1):
            try:
                return await self.masked_fetch()
            except Exception as exc:
                last_exc = exc
                if attempt < max_retries:
                    sleep_max  = min(cap, delay * (2 ** (attempt - 1)))
                    sleep_time = random.uniform(0, sleep_max)   # full jitter
                    await asyncio.sleep(sleep_time)

        raise SourceError(
            source_name=self.label,
            cause=last_exc,   # type: ignore[arg-type]
            attempts=max_retries,
        ) from last_exc

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.type!r}>"
