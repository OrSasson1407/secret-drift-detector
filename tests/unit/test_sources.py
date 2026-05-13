import pytest
import tempfile
import os
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from detector.sources import _hash, SecretSnapshot, BaseSource
from detector.sources.dotenv_file import DotEnvSource
from detector.sources.ssm import SSMSource


# ---------------------------------------------------------------------------
# _hash
# ---------------------------------------------------------------------------

def test_hash_deterministic():
    assert _hash("hello") == _hash("hello")


def test_hash_different_inputs():
    assert _hash("abc") != _hash("xyz")


def test_hash_is_hex_string():
    h = _hash("test")
    assert len(h) == 64
    int(h, 16)  # should not raise


# ---------------------------------------------------------------------------
# BaseSource.masked_fetch
# ---------------------------------------------------------------------------

class _FakeSource(BaseSource):
    type = "fake"
    async def fetch(self) -> SecretSnapshot:
        return SecretSnapshot(
            source="fake",
            fetched_at=datetime.now(timezone.utc),
            secrets={"MY_PASSWORD": "plaintext", "APP_NAME": "myapp"},
        )


@pytest.mark.asyncio
async def test_masked_fetch_hashes_values():
    src  = _FakeSource()
    snap = await src.masked_fetch()
    assert snap.secrets["MY_PASSWORD"] == _hash("plaintext")
    assert snap.secrets["APP_NAME"]    == _hash("myapp")


@pytest.mark.asyncio
async def test_masked_fetch_no_plaintext():
    src  = _FakeSource()
    snap = await src.masked_fetch()
    assert "plaintext" not in snap.secrets.values()


# ---------------------------------------------------------------------------
# fetch_with_retry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_with_retry_succeeds_first_try():
    src  = _FakeSource()
    snap = await src.fetch_with_retry(max_retries=3, delay=0)
    assert snap.source == "fake"


@pytest.mark.asyncio
async def test_fetch_with_retry_raises_after_exhaustion():
    class _BrokenSource(BaseSource):
        type = "broken"
        async def fetch(self):
            raise ConnectionError("unreachable")

    src = _BrokenSource()
    with pytest.raises(Exception, match="failed after 2 attempt"):
        await src.fetch_with_retry(max_retries=2, delay=0)


# ---------------------------------------------------------------------------
# DotEnvSource
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dotenv_source_reads_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("DB_PASSWORD=hunter2\nAPP_NAME=myapp\n")
        path = f.name
    try:
        src  = DotEnvSource(path=path)
        snap = await src.fetch()
        assert snap.secrets["DB_PASSWORD"] == "hunter2"
        assert snap.secrets["APP_NAME"]    == "myapp"
        assert snap.source.startswith("dotenv:")
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_dotenv_source_skips_empty_values():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("PRESENT=value\nEMPTY=\n")
        path = f.name
    try:
        src  = DotEnvSource(path=path)
        snap = await src.fetch()
        assert "PRESENT" in snap.secrets
        assert snap.secrets["EMPTY"] == ""
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# SSMSource (mocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssm_source_strips_prefix():
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = iter([{
        "Parameters": [
            {"Name": "/prod/myapp/DB_PASSWORD", "Value": "secret"},
            {"Name": "/prod/myapp/APP_NAME",    "Value": "myapp"},
        ]
    }])

    with patch("boto3.client") as mock_boto:
        mock_boto.return_value.get_paginator.return_value = mock_paginator
        src  = SSMSource(prefix="/prod/myapp/", region="us-east-1")
        snap = await src.fetch()

    assert snap.secrets["DB_PASSWORD"] == "secret"
    assert snap.secrets["APP_NAME"]    == "myapp"
    assert snap.source == "ssm:/prod/myapp/"



