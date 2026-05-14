import asyncio
from detector.runtime import BaseProber


class K8sExecProber(BaseProber):
    """Probe a Kubernetes pod's live environment via kubectl exec.

    Requires kubectl on PATH and appropriate RBAC (pods/exec verb).

    Example target config:
        [[targets]]
        type      = "k8s_exec"
        pod       = "myapp-6d4b9f-xk2p7"
        namespace = "production"
        container = "app"           # optional; first container used if omitted
    """

    type = "k8s_exec"

    def __init__(
        self,
        pod:          str,
        namespace:    str = "default",
        container:    str | None = None,
        strip_system: bool = True,
        extra_strip:  set[str] | None = None,
    ):
        self.pod          = pod
        self.namespace    = namespace
        self.container    = container
        self.strip_system = strip_system
        self.extra_strip  = extra_strip

    async def probe(self) -> dict[str, str]:
        cmd = ["kubectl", "exec", self.pod, "-n", self.namespace]

        if self.container:
            cmd += ["-c", self.container]

        cmd += ["--", "env"]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode().strip()
            raise RuntimeError(
                f"K8sExecProber: kubectl exec failed for pod '{self.pod}' "
                f"(namespace='{self.namespace}'): {err}"
            )

        raw = self._parse_env_output(stdout.decode())
        return self.filter_env(raw, strip_system=self.strip_system, extra_strip=self.extra_strip)
