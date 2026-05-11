from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel, Field


class SecretSnapshot(BaseModel):
    source:     str
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    secrets:    dict[str, str] = Field(default_factory=dict)
    metadata:   dict           = Field(default_factory=dict)


class BaseSource(ABC):
    label: str = "unknown"

    @abstractmethod
    async def fetch(self) -> SecretSnapshot: ...

    async def masked_fetch(self) -> SecretSnapshot:
        snap = await self.fetch()
        snap.secrets = {
            k: hashlib.sha256(v.encode()).hexdigest()
            for k, v in snap.secrets.items()
        }
        return snap


def merge_snapshots(snapshots: list[SecretSnapshot]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for snap in snapshots:
        merged.update(snap.secrets)
    return merged
