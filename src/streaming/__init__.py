"""Streaming Module — Real-time Data Pipeline"""

from .producer import FlowProducer, ProducerConfig, FlowProducerFactory, CompressionType
from .consumer import FlowConsumer, ConsumerConfig, DetectionConsumer, AutoOffsetReset
from .window_aggregator import (
    WindowAggregator,
    TimeWindow,
    AggregatedStats,
    RealtimeAggregator,
)
# FIX BUG-37: SecureKafkaClient and SecureRedisClient were not exported,
# forcing callers to reach into the private module path.  Added here so users
# can do: from src.streaming import SecureKafkaClient
from .secure_client import SecureKafkaClient, SecureRedisClient, SecureClientConfig

__all__ = [
    # Producer
    'FlowProducer',
    'ProducerConfig',
    'FlowProducerFactory',
    'CompressionType',
    # Consumer
    'FlowConsumer',
    'ConsumerConfig',
    'DetectionConsumer',
    'AutoOffsetReset',
    # Window aggregation
    'WindowAggregator',
    'RealtimeAggregator',
    'TimeWindow',
    'AggregatedStats',
    # Secure clients
    'SecureKafkaClient',
    'SecureRedisClient',
    'SecureClientConfig',
]