import base64
import asyncio
from datetime import datetime, timezone
from detector.sources import BaseSource, SecretSnapshot

class KubernetesSource(BaseSource):
    type = "kubernetes"
    
    def __init__(self, namespace: str = "default", label_selector: str = None):
        self.namespace = namespace or "default"
        self.label_selector = label_selector
        self.client = None

    async def fetch(self) -> SecretSnapshot:
        if not self.client:
            from kubernetes import client, config
            try:
                config.load_incluster_config()
            except Exception:
                try:
                    config.load_kube_config()
                except Exception:
                    pass
            self.client = client.CoreV1Api()

        loop = asyncio.get_running_loop()
        kwargs = {"namespace": self.namespace}
        if self.label_selector:
            kwargs["label_selector"] = self.label_selector
            
        secrets_list = await loop.run_in_executor(
            None, 
            lambda: self.client.list_namespaced_secret(**kwargs)
        )
        
        extracted_secrets = {}
        for secret in secrets_list.items:
            if secret.data:
                for key, val in secret.data.items():
                    try:
                        decoded = base64.b64decode(val).decode("utf-8")
                        extracted_secrets[f"{secret.metadata.name}/{key}"] = decoded
                    except Exception:
                        pass
                        
        return SecretSnapshot(
            source=f"kubernetes:{self.namespace}",
            fetched_at=datetime.now(timezone.utc),
            secrets=extracted_secrets,
            metadata={"namespace": self.namespace}
        )
