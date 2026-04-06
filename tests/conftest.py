"""Pytest configuration: ensure project root is on sys.path so `import src` works from any CWD."""

from __future__ import annotations

import sys
import time
import pytest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# FIX BUG-38: In pytest-asyncio ≥0.21 the session-scoped custom event_loop
# fixture is deprecated.  Modern pytest-asyncio manages the loop automatically
# when asyncio_mode is set to "auto" in pytest.ini / pyproject.toml.
# The custom fixture is removed here; tests that require asyncio should use
# pytest.mark.asyncio or configure asyncio_mode="auto".


@pytest.fixture
def sample_flow() -> dict:
    """Provide a sample flow dictionary for testing."""
    return {
        'flow_id': 'test_flow_001',
        'ip_src': '192.168.1.100',
        'ip_dst': '10.0.0.1',
        'sport': 54321,
        'dport': 80,
        'protocol': 6,
        'total_packets': 150,
        'total_bytes': 15_000,
        'packets_per_sec': 50.0,
        'bytes_per_sec': 5_000.0,
        'duration': 3.0,
        'first_seen': time.time() - 3.0,
        'last_seen': time.time(),
    }


@pytest.fixture
def sample_attack_flow() -> dict:
    """Provide a sample attack flow for testing."""
    return {
        'flow_id': 'attack_flow_001',
        'ip_src': '192.168.1.200',
        'ip_dst': '10.0.0.1',
        'sport': 12345,
        'dport': 80,
        'protocol': 6,
        'total_packets': 1_000,
        'total_bytes': 60_000,
        'packets_per_sec': 1_000.0,
        'bytes_per_sec': 60_000.0,
        'duration': 1.0,
        'tcp_syn_count': 1,
        'tcp_syn_ack_count': 0,
    }