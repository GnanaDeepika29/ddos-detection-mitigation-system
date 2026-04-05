"""Streaming Module - Real-time Data Pipeline"""

from .producer import FlowProducer, ProducerConfig, FlowProducerFactory, CompressionType
from .consumer import FlowConsumer, ConsumerConfig, DetectionConsumer, AutoOffsetReset
from .window_aggregator import (
    WindowAggregator,
    TimeWindow,
    AggregatedStats,
    RealtimeAggregator,
)

__all__ = [
    'FlowProducer',
    'ProducerConfig',
    'FlowProducerFactory',
    'CompressionType',
    'FlowConsumer',
    'ConsumerConfig',
    'DetectionConsumer',
    'AutoOffsetReset',
    'WindowAggregator',
    'RealtimeAggregator',
    'TimeWindow',
    'AggregatedStats',
]