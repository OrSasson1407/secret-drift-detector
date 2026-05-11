from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel
import hashlib

def _hash(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

class SecretSnapshot(BaseModel):
    source: str
    fetched_at: datetime
    secrets: dict[str, str] # key: plaintext value
    metadata: dict = {}

class BaseSource(ABC):
    @abstractmethod
    async def fetch(self) -> SecretSnapshot:
        pass

    async def masked_fetch(self) -> SecretSnapshot:
        snap = await self.fetch()
        snap.secrets = {k: _hash(v) for k, v in snap.secrets.items()}
        return snap
