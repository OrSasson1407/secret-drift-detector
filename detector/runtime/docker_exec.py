import asyncio
from detector.runtime import BaseProber

class DockerExecProber(BaseProber):
    def __init__(self, container_name: str):
        self.container_name = container_name

    async def probe(self) -> dict[str, str]:
        # Run docker exec <container> env
        process = await asyncio.create_subprocess_exec(
            'docker', 'exec', self.container_name, 'env',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Docker exec failed: {stderr.decode().strip()}")
            
        env_vars = {}
        for line in stdout.decode().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value
        return env_vars
