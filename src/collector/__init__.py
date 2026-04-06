"""Collector Module — Traffic Ingestion"""

from .packet_capture import PacketCapture, PacketCaptureConfig
from .flow_builder import FlowBuilder, Flow, FlowKey, FlowStats
from .cloud_agent import (
    CloudFlowLogAgent,
    CloudFlowLogConfig,
    CloudProvider,
    # NOTE (BUG-38): FlowLogSource is exported for API completeness but is not
    # used internally — cloud routing is keyed on CloudProvider, not
    # FlowLogSource.  Callers may use it for labelling / metadata purposes.
    FlowLogSource,
)

__all__ = [
    'PacketCapture',
    'PacketCaptureConfig',
    'FlowBuilder',
    'Flow',
    'FlowKey',
    'FlowStats',
    'CloudFlowLogAgent',
    'CloudFlowLogConfig',
    'CloudProvider',
    'FlowLogSource',
]