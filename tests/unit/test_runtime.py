import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from detector.runtime import BaseProber
from detector.runtime.local_env      import LocalEnvProber
from detector.runtime.docker_exec    import DockerExecProber
from detector.runtime.http_introspect import HttpIntrospectProber


# ---------------------------------------------------------------------------
# BaseProber._parse_env_output
# ---------------------------------------------------------------------------

class _ConcreteProber(BaseProber):
    type = "test"
    async def probe(self): return {}


def test_parse_env_output_basic():
    raw = "KEY=value\nDB_PASSWORD=s3cr3t\nAPP_NAME=myapp"
    env = _ConcreteProber._parse_env_output(raw)
    assert env["KEY"] == "value"
    assert env["DB_PASSWORD"] == "s3cr3t"
    assert env["APP_NAME"] == "myapp"


def test_parse_env_output_value_with_equals():
    raw = "ENCODED=abc=def=ghi"
    env = _ConcreteProber._parse_env_output(raw)
    assert env["ENCODED"] == "abc=def=ghi"


def test_parse_env_output_skips_no_equals():
    raw = "VALID=yes\nNO_EQUALS_HERE\nALSO_VALID=1"
    env = _ConcreteProber._parse_env_output(raw)
    assert "NO_EQUALS_HERE" not in env
    assert len(env) == 2


# ---------------------------------------------------------------------------
# LocalEnvProber
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_env_prober_returns_env(monkeypatch):
    monkeypatch.setenv("TEST_LOCAL_KEY", "hello")
    prober = LocalEnvProber()
    env    = await prober.probe()
    assert env["TEST_LOCAL_KEY"] == "hello"


@pytest.mark.asyncio
async def test_local_env_prober_key_filter(monkeypatch):
    monkeypatch.setenv("APP_NAME",  "myapp")
    monkeypatch.setenv("APP_PORT",  "8080")
    monkeypatch.setenv("DB_PASS",   "secret")
    prober = LocalEnvProber(key_filter=["APP_"])
    env    = await prober.probe()
    assert "APP_NAME" in env
    assert "APP_PORT" in env
    assert "DB_PASS"  not in env


# ---------------------------------------------------------------------------
# DockerExecProber
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_docker_exec_prober_parses_output():
    mock_proc        = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(
        return_value=(b"DB_PASSWORD=secret\nAPP_NAME=myapp\n", b"")
    )
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        prober = DockerExecProber(container_name="web_1")
        env    = await prober.probe()
    assert env["DB_PASSWORD"] == "secret"
    assert env["APP_NAME"]    == "myapp"


@pytest.mark.asyncio
async def test_docker_exec_prober_raises_on_failure():
    mock_proc            = AsyncMock()
    mock_proc.returncode = 1
    mock_proc.communicate = AsyncMock(return_value=(b"", b"No such container"))
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        prober = DockerExecProber(container_name="missing_container")
        with pytest.raises(RuntimeError, match="docker exec failed"):
            await prober.probe()


# ---------------------------------------------------------------------------
# HttpIntrospectProber
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_introspect_parses_json():
    mock_resp         = AsyncMock()
    mock_resp.status  = 200
    mock_resp.json    = AsyncMock(return_value={"DB_PASSWORD": "secret", "PORT": "8080"})

    mock_session      = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__  = AsyncMock(return_value=False)
    mock_session.get        = MagicMock(return_value=AsyncMock(
        __aenter__=AsyncMock(return_value=mock_resp),
        __aexit__=AsyncMock(return_value=False),
    ))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        prober = HttpIntrospectProber(url="http://app/_debug/env")
        env    = await prober.probe()

    assert env["DB_PASSWORD"] == "secret"
    assert env["PORT"]        == "8080"


@pytest.mark.asyncio
async def test_http_introspect_raises_on_bad_status():
    mock_resp        = AsyncMock()
    mock_resp.status = 403

    mock_session     = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__  = AsyncMock(return_value=False)
    mock_session.get        = MagicMock(return_value=AsyncMock(
        __aenter__=AsyncMock(return_value=mock_resp),
        __aexit__=AsyncMock(return_value=False),
    ))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        prober = HttpIntrospectProber(url="http://app/_debug/env")
        with pytest.raises(RuntimeError, match="HTTP 403"):
            await prober.probe()
