import pytest
from detector.runtime.docker_exec import DockerExecProber

@pytest.mark.asyncio
async def test_docker_exec_prober_initialization():
    # Tests the docker exec prober setup
    prober = DockerExecProber(container_name="test-container")
    assert prober.container_name == "test-container"
    assert prober.type == "docker"
