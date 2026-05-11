import os
from detector.runtime import BaseProber


class ProcEnvironProber(BaseProber):
    type = "proc"

    def __init__(self, pid_file: str):
        self.pid_file = pid_file

    async def probe(self) -> dict[str, str]:
        with open(self.pid_file, "r") as f:
            pid = f.read().strip()

        path = f"/proc/{pid}/environ"
        if not os.path.exists(path):
            raise FileNotFoundError(f"ProcEnvironProber: {path} not found")

        with open(path, "rb") as f:
            data = f.read()

        env: dict[str, str] = {}
        for entry in data.split(b"\x00"):
            decoded = entry.decode("utf-8", errors="replace")
            if "=" in decoded:
                k, v = decoded.split("=", 1)
                env[k] = v
        return env
