import asyncio
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from detector.sources import BaseSource, SecretSnapshot, SourceError


class SecretsManagerSource(BaseSource):
    """AWS Secrets Manager source adapter.

    Supports both plain-string secrets and JSON-encoded multi-key secrets.
    Multiple secret names or ARNs can be provided as a comma-separated string
    in the 'path' config field, e.g.:

        [[sources]]
        type   = "secrets_manager"
        path   = "myapp/db-password, myapp/api-keys"
        region = "us-east-1"

    JSON secrets (e.g. {"DB_PASS": "x", "API_KEY": "y"}) are automatically
    expanded into individual keys.  Plain-string secrets use the final
    segment of the secret name as the key.
    """

    type = "secrets_manager"

    def __init__(
        self,
        path:       str,
        region:     str,
        key_prefix: str | None = None,
    ):
        # Accept comma-separated list of secret names / ARNs
        self.secret_ids = [s.strip() for s in path.split(",") if s.strip()]
        self.region     = region
        self.key_prefix = key_prefix.rstrip("/") + "/" if key_prefix else None
        self.client     = boto3.client("secretsmanager", region_name=region)

    @property
    def label(self) -> str:
        ids = ", ".join(self.secret_ids[:2])
        suffix = f" +{len(self.secret_ids)-2} more" if len(self.secret_ids) > 2 else ""
        return f"SecretsManagerSource(region={self.region!r}, secrets=[{ids}{suffix}])"

    def _fetch_one(self, secret_id: str) -> dict[str, str]:
        try:
            resp = self.client.get_secret_value(SecretId=secret_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                raise SourceError(
                    self.label,
                    KeyError(f"Secret '{secret_id}' not found in Secrets Manager"),
                ) from exc
            if code in ("AccessDeniedException", "InvalidRequestException"):
                raise SourceError(
                    self.label,
                    PermissionError(f"Access denied to '{secret_id}' ({code})"),
                ) from exc
            if code == "DecryptionFailure":
                raise SourceError(
                    self.label,
                    RuntimeError(f"KMS decryption failed for '{secret_id}'"),
                ) from exc
            raise SourceError(self.label, exc) from exc

        raw_value = resp.get("SecretString") or ""

        # Attempt to parse as a JSON dict (multi-key secret)
        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except (json.JSONDecodeError, ValueError):
            pass

        # Plain string secret — derive key name from the secret identifier
        key = secret_id.split("/")[-1].split(":")[-1]
        return {key: raw_value}

    def _fetch_all_sync(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for sid in self.secret_ids:
            partial = self._fetch_one(sid)
            if self.key_prefix:
                partial = {
                    (k[len(self.key_prefix):] if k.startswith(self.key_prefix) else k): v
                    for k, v in partial.items()
                }
            merged.update(partial)
        return merged

    async def fetch(self) -> SecretSnapshot:
        secrets = await asyncio.to_thread(self._fetch_all_sync)
        return SecretSnapshot(
            source=f"secrets_manager:{self.region}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
            metadata={"secret_count": len(self.secret_ids), "key_count": len(secrets)},
        )
