"""Pytest: ensure project root is on sys.path so `import src` works from any CWD."""

from __future__ import annotations

import sys
import pytest
import asyncio
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_flow():
    """Provide a sample flow dictionary for testing."""
    return {
        'flow_id': 'test_flow_001',
        'ip_src': '192.168.1.100',
        'ip_dst': '10.0.0.1',
        'sport': 54321,
        'dport': 80,
        'protocol': 6,
        'total_packets': 150,
        'total_bytes': 15000,
        'packets_per_sec': 50.0,
        'bytes_per_sec': 5000.0,
        'duration': 3.0,
        'first_seen': 1234567890.0,
        'last_seen': 1234567893.0,
    }


@pytest.fixture
def sample_attack_flow():
    """Provide a sample attack flow for testing."""
    return {
        'flow_id': 'attack_flow_001',
        'ip_src': '192.168.1.200',
        'ip_dst': '10.0.0.1',
        'sport': 12345,
        'dport': 80,
        'protocol': 6,
        'total_packets': 1000,
        'total_bytes': 60000,
        'packets_per_sec': 1000.0,
        'bytes_per_sec': 60000.0,
        'duration': 1.0,
        'tcp_syn_count': 1,
        'tcp_syn_ack_count': 0,
    }