import asyncio
from datetime import datetime, timezone
from google.cloud import secretmanager
from detector.sources import BaseSource, SecretSnapshot

class GCPSource(BaseSource):
    def __init__(self, project_id: str = None):
        # Fallback to a placeholder if not provided, allowing instantiation in tests/CI
        self.project_id = project_id or "default-gcp-project" 
        try:
            self.client = secretmanager.SecretManagerServiceClient()
        except Exception as e:
            print(f"[GCPSource] Warning: Could not initialize GCP client: {e}")
            self.client = None

    async def fetch(self) -> SecretSnapshot:
        if not self.client:
            return SecretSnapshot(
                source=self.label,
                fetched_at=datetime.now(timezone.utc),
                secrets={},
                metadata={"error": "GCP Client not initialized"}
            )

        loop = asyncio.get_running_loop()
        
        def _fetch_secrets():
            parent = f"projects/{self.project_id}"
            secrets_dict = {}
            try:
                for secret in self.client.list_secrets(request={"parent": parent}):
                    secret_name = secret.name.split('/')[-1]
                    version_path = self.client.secret_version_path(self.project_id, secret_name, "latest")
                    try:
                        response = self.client.access_secret_version(request={"name": version_path})
                        payload = response.payload.data.decode("UTF-8")
                        secrets_dict[secret_name] = payload
                    except Exception as e:
                        print(f"[GCPSource] Warning: Could not access secret {secret_name}: {e}")
            except Exception as e:
                print(f"[GCPSource] Failed to list secrets: {e}")
            return secrets_dict

        # Wrap the synchronous GCP API call to avoid blocking the async event loop
        extracted_secrets = await loop.run_in_executor(None, _fetch_secrets)

        return SecretSnapshot(
            source=self.label,
            fetched_at=datetime.now(timezone.utc),
            secrets=extracted_secrets,
            metadata={"project_id": self.project_id}
        )
