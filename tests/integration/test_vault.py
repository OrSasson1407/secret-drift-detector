import pytest
from detector.sources.vault import VaultSource

@pytest.mark.asyncio
async def test_vault_source_initialization():
    # Basic integration test ensuring Vault properties construct correctly
    source = VaultSource(addr="http://localhost:8200", path="secret/data/test", token="test-token")
    assert source.addr == "http://localhost:8200"
    assert source.path == "secret/data/test"
    assert source.label == "vault:secret/data/test"
