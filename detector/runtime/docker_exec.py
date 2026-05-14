import asyncio
from detector.runtime import BaseProber


class DockerExecProber(BaseProber):
    type = "docker"

    def __init__(
        self,
        container_name: str,
        strip_system:   bool       = True,
        extra_strip:    set[str] | None = None,
    ):
        self.container_name = container_name
        self.strip_system   = strip_system
        self.extra_strip    = extra_strip

    async def probe(self) -> dict[str, str]:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.container_name, "env",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"DockerExecProber: docker exec failed for '{self.container_name}': "
                f"{stderr.decode().strip()}"
            )

        raw = self._parse_env_output(stdout.decode())
        return self.filter_env(raw, strip_system=self.strip_system, extra_strip=self.extra_strip)
