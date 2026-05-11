import os
from detector.runtime import BaseProber

class ProcEnvironProber(BaseProber):
    def __init__(self, pid_file: str):
        self.pid_file = pid_file

    def _get_pid(self) -> str:
        with open(self.pid_file, 'r') as f:
            return f.read().strip()

    async def probe(self) -> dict[str, str]:
        pid = self._get_pid()
        environ_path = f"/proc/{pid}/environ"
        
        if not os.path.exists(environ_path):
            raise FileNotFoundError(f"Process environment file not found: {environ_path}")
            
        env_vars = {}
        with open(environ_path, 'r') as f:
            data = f.read()
            # /proc/pid/environ is null-byte separated
            for item in data.split('\0'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    env_vars[key] = value
                    
        return env_vars
