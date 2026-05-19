import pytest
from unittest.mock import MagicMock, patch
from detector.agent import Agent
from detector.config import DetectorConfig
from detector.diff.models import DriftReport

@pytest.mark.asyncio
async def test_agent_run_once_initializes():
    config_data = {
        "agent": {"interval_seconds": 60, "db_path": "test.db"},
        "sources": [],
        "targets": [],
        "alerts": {},
        "remediation": {"enabled": False}
    }
    config = DetectorConfig(**config_data)
    agent = Agent(config)
    agent.storage = MagicMock()
    agent.storage.save_report.return_value = 1
    
    report = await agent.run_once()
    assert isinstance(report, DriftReport)
    agent.storage.save_report.assert_called_once()
