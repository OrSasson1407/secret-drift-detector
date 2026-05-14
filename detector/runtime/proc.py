import os
from detector.runtime import BaseProber


class ProcEnvironProber(BaseProber):
    type = "proc"

    def __init__(
        self,
        pid_file:     str,
        strip_system: bool       = True,
        extra_strip:  set[str] | None = None,
    ):
        self.pid_file     = pid_file
        self.strip_system = strip_system
        self.extra_strip  = extra_strip

    async def probe(self) -> dict[str, str]:
        try:
            with open(self.pid_file, "r") as f:
                pid = f.read().strip()
        except OSError as exc:
            raise RuntimeError(
                f"ProcEnvironProber: cannot read pid file '{self.pid_file}': {exc}"
            ) from exc

        environ_path = f"/proc/{pid}/environ"
        if not os.path.exists(environ_path):
            raise FileNotFoundError(
                f"ProcEnvironProber: {environ_path} not found — "
                f"is the process (pid={pid}) still running?"
            )

        try:
            with open(environ_path, "rb") as f:
                data = f.read()
        except PermissionError as exc:
            raise RuntimeError(
                f"ProcEnvironProber: permission denied reading {environ_path} — "
                "run as root or grant CAP_SYS_PTRACE"
            ) from exc

        raw: dict[str, str] = {}
        for entry in data.split(b"\x00"):
            decoded = entry.decode("utf-8", errors="replace")
            if "=" in decoded:
                k, v = decoded.split("=", 1)
                raw[k] = v

        return self.filter_env(raw, strip_system=self.strip_system, extra_strip=self.extra_strip)
