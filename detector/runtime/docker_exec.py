import asyncio
from detector.runtime import BaseProber


class DockerExecProber(BaseProber):
    type = "docker"

    def __init__(self, container_name: str):
        self.container_name = container_name

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

        return self._parse_env_output(stdout.decode())
