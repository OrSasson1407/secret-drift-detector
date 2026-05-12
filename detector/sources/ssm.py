import asyncio
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from detector.sources import BaseSource, SecretSnapshot, SourceError


class SSMSource(BaseSource):
    type = "ssm"

    def __init__(
        self,
        prefix: str,
        region: str,
        key_prefix: str | None = None,
    ):
        self.prefix     = prefix.rstrip("/") + "/"
        self.region     = region
        self.key_prefix = key_prefix.rstrip("/") + "/" if key_prefix else None
        self.client     = boto3.client("ssm", region_name=region)

    @property
    def label(self) -> str:
        return f"SSMSource(prefix={self.prefix!r}, region={self.region!r})"

    def _fetch_sync(self) -> tuple[dict[str, str], dict[str, str]]:
        paginator = self.client.get_paginator("get_parameters_by_path")
        secrets:  dict[str, str] = {}
        metadata: dict[str, str] = {}

        try:
            for page in paginator.paginate(Path=self.prefix, WithDecryption=True):
                for param in page["Parameters"]:
                    # Strip the SSM path prefix to get a clean key name
                    key = param["Name"][len(self.prefix):]

                    # Optionally strip an additional key_prefix
                    if self.key_prefix and key.startswith(self.key_prefix):
                        key = key[len(self.key_prefix):]

                    secrets[key] = param["Value"]

                    # Capture last-modified date for staleness tracking
                    last_mod = param.get("LastModifiedDate")
                    if last_mod:
                        metadata[key] = last_mod.isoformat()

        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ThrottlingException":
                raise SourceError(
                    self.label,
                    RuntimeError("AWS SSM rate limit hit — reduce poll frequency"),
                ) from exc
            if code in ("AccessDeniedException", "InvalidKeyId"):
                raise SourceError(
                    self.label,
                    PermissionError(f"SSM access denied ({code}) for prefix '{self.prefix}'"),
                ) from exc
            raise SourceError(self.label, exc) from exc

        return secrets, metadata

    async def fetch(self) -> SecretSnapshot:
        secrets, last_modified = await asyncio.to_thread(self._fetch_sync)
        return SecretSnapshot(
            source=f"ssm:{self.prefix}",
            fetched_at=datetime.now(timezone.utc),
            secrets=secrets,
            metadata={"last_modified": last_modified, "key_count": len(secrets)},
        )
