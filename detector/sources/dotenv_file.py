from __future__ import annotations

import asyncio
from pathlib import Path

from dotenv import dotenv_values

from . import BaseSource, SecretSnapshot


class DotenvSource(BaseSource):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.label = f"dotenv:{path}"

    async def fetch(self) -> SecretSnapshot:
        if not self.path.exists():
            raise FileNotFoundError(f".env file not found: {self.path}")

        values = await asyncio.to_thread(dotenv_values, self.path)

        return SecretSnapshot(
            source=self.label,
            secrets={k: v for k, v in values.items() if v is not None},
        )
