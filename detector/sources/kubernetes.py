import base64
import asyncio
from datetime import datetime, timezone
from kubernetes import client, config
from detector.sources import BaseSource, SecretSnapshot

class KubernetesSource(BaseSource):
    def __init__(self, namespace: str = "default", label_selector: str = None):
        self.namespace = namespace or "default"
        self.label_selector = label_selector
        
        # Load Kubernetes config (supports both local kubeconfig and in-cluster CI service accounts)
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except Exception as e:
                print(f"[KubernetesSource] Warning: Could not load k8s config: {e}")
        
        self.v1 = client.CoreV1Api()

    async def fetch(self) -> SecretSnapshot:
        # Wrap the synchronous K8s API call in an executor to prevent blocking the async event loop
        loop = asyncio.get_running_loop()
        kwargs = {"namespace": self.namespace}
        if self.label_selector:
            kwargs["label_selector"] = self.label_selector
            
        secrets_list = await loop.run_in_executor(
            None, 
            lambda: self.v1.list_namespaced_secret(**kwargs)
        )
        
        extracted_secrets = {}
        for secret in secrets_list.items:
            if secret.data:
                for key, val in secret.data.items():
                    try:
                        # K8s secrets are base64 encoded by default
                        decoded = base64.b64decode(val).decode("utf-8")
                        extracted_secrets[f"{secret.metadata.name}/{key}"] = decoded
                    except Exception:
                        pass
                        
        return SecretSnapshot(
            source=self.label,
            fetched_at=datetime.now(timezone.utc),
            secrets=extracted_secrets,
            metadata={"namespace": self.namespace}
        )
