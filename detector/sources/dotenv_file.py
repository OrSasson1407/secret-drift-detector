import os
from datetime import datetime, timezone

from detector.sources import BaseSource, SecretSnapshot, SourceError


class DotEnvSource(BaseSource):
    type = "dotenv"

    def __init__(self, path: str, encoding: str = "utf-8"):
        self.path     = path
        self.encoding = encoding

    @property
    def label(self) -> str:
        return f"DotEnvSource(path={self.path!r})"

    async def fetch(self) -> SecretSnapshot:
        if not os.path.exists(self.path):
            raise SourceError(
                self.label,
                FileNotFoundError(f"dotenv file not found: '{self.path}'"),
            )

        try:
            mtime = os.path.getmtime(self.path)
            mtime_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

            secrets: dict[str, str] = {}
            with open(self.path, encoding=self.encoding, errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key   = key.strip()
                    value = value.strip().strip("'\"")   # unquote simple values
                    if key:
                        secrets[key] = value

        except OSError as exc:
            raise SourceError(self.label, exc) from exc

        return SecretSnapshot(
            source=f"dotenv:{self.path}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
            metadata={"file_mtime": mtime_iso, "key_count": len(secrets)},
        )
