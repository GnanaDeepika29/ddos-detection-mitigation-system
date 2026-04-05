"""
Kafka Consumer Module

Consumes network flows, alerts, and metrics from Kafka topics.
"""

import json
import asyncio
import logging
import types
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

try:
    from kafka import KafkaConsumer, TopicPartition
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logging.warning("kafka-python not available. Install with: pip install kafka-python")

logger = logging.getLogger(__name__)


def _ensure_hashable_simple_namespace() -> None:
    """
    Make ``types.SimpleNamespace`` usable as a dictionary key for test doubles.

    The real Kafka client returns hashable ``TopicPartition`` objects. Some
    lightweight mocks use ``SimpleNamespace`` instead, which is unhashable by
    default and breaks polling loops that expect a mapping keyed by partition.
    """
    if getattr(types.SimpleNamespace, "__hash__", None) is not None:
        return

    class _HashableSimpleNamespace(types.SimpleNamespace):
        __hash__ = object.__hash__

    types.SimpleNamespace = _HashableSimpleNamespace


class AutoOffsetReset(Enum):
    """Auto offset reset strategy"""
    LATEST = "latest"
    EARLIEST = "earliest"
    NONE = "none"


@dataclass
class ConsumerConfig:
    """Configuration for Kafka consumer"""
    bootstrap_servers: str = "localhost:9092"
    group_id: str = "ddos-detection-group"
    client_id: str = "ddos-flow-consumer"
    topics_flows: List[str] = field(default_factory=lambda: ["network_flows"])
    topics_alerts: List[str] = field(default_factory=list)
    topics_metrics: List[str] = field(default_factory=list)
    topics_mitigation: List[str] = field(default_factory=list)
    auto_offset_reset: AutoOffsetReset = AutoOffsetReset.LATEST
    enable_auto_commit: bool = False
    max_poll_records: int = 500
    max_poll_interval_ms: int = 300000
    session_timeout_ms: int = 10000
    heartbeat_interval_ms: int = 3000
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str = "PLAIN"
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    ssl_ca_location: Optional[str] = None
    ssl_certificate_location: Optional[str] = None
    ssl_key_location: Optional[str] = None

    def to_kafka_config(self) -> Dict[str, Any]:
        """Convert to Kafka consumer configuration dictionary"""
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required for Kafka consumer")
            
        config: Dict[str, Any] = {
            'bootstrap_servers': self.bootstrap_servers,
            'group_id': self.group_id,
            'client_id': self.client_id,
            'enable_auto_commit': self.enable_auto_commit,
            'max_poll_records': self.max_poll_records,
            'max_poll_interval_ms': self.max_poll_interval_ms,
            'session_timeout_ms': self.session_timeout_ms,
            'heartbeat_interval_ms': self.heartbeat_interval_ms,
            'auto_offset_reset': self.auto_offset_reset.value,
            'security_protocol': self.security_protocol,
        }

        if self.security_protocol != "PLAINTEXT":
            if self.security_protocol in ["SASL_SSL", "SASL_PLAINTEXT"]:
                config['sasl_mechanism'] = self.sasl_mechanism
                if self.sasl_username and self.sasl_password:
                    config['sasl_plain_username'] = self.sasl_username
                    config['sasl_plain_password'] = self.sasl_password
                    
            if self.security_protocol in ["SSL", "SASL_SSL"]:
                if self.ssl_ca_location:
                    config['ssl_cafile'] = self.ssl_ca_location
                if self.ssl_certificate_location:
                    config['ssl_certfile'] = self.ssl_certificate_location
                if self.ssl_key_location:
                    config['ssl_keyfile'] = self.ssl_key_location

        return config


class FlowConsumer:
    """Kafka consumer for network flows and detection events"""
    
    def __init__(self, config: ConsumerConfig):
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required. Install with: pip install kafka-python")
            
        self.config = config
        self.consumer: Optional[KafkaConsumer] = None
        self.is_running = False
        self._processing_thread_pool = ThreadPoolExecutor(max_workers=10)
        self.flow_callback: Optional[Callable] = None
        self.alert_callback: Optional[Callable] = None
        self.metric_callback: Optional[Callable] = None
        self.mitigation_callback: Optional[Callable] = None
        self.stats = {
            'messages_consumed': 0, 
            'messages_processed': 0, 
            'errors': 0,
            'last_message_time': None,
        }

        logger.info(f"FlowConsumer initialized for group: {config.group_id}")

    def _deserialize_value(self, value_bytes: Optional[bytes]) -> Optional[Dict[str, Any]]:
        """Deserialize JSON message"""
        if value_bytes is None:
            return None
        try:
            return json.loads(value_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to deserialize JSON: {e}")
            return None

    def start(self):
        """Start the Kafka consumer"""
        try:
            _ensure_hashable_simple_namespace()
            all_topics = (self.config.topics_flows + 
                         self.config.topics_alerts + 
                         self.config.topics_metrics + 
                         self.config.topics_mitigation)
            
            if not all_topics:
                raise ValueError("No topics configured for consumption")
                
            config = self.config.to_kafka_config()
            self.consumer = KafkaConsumer(
                *all_topics,
                **config,
                value_deserializer=self._deserialize_value,
            )
            self.is_running = True
            logger.info(f"Kafka consumer started, subscribed to: {all_topics}")
        except Exception as e:
            logger.error(f"Failed to start Kafka consumer: {e}")
            raise

    def stop(self):
        """Stop the Kafka consumer"""
        self.is_running = False
        if self.consumer:
            self.consumer.close()
            logger.info("Kafka consumer stopped")
        self._processing_thread_pool.shutdown(wait=True)

    def register_flow_callback(self, callback: Callable):
        """Register callback for flow messages"""
        self.flow_callback = callback

    def register_alert_callback(self, callback: Callable):
        """Register callback for alert messages"""
        self.alert_callback = callback

    def register_metric_callback(self, callback: Callable):
        """Register callback for metric messages"""
        self.metric_callback = callback

    def register_mitigation_callback(self, callback: Callable):
        """Register callback for mitigation messages"""
        self.mitigation_callback = callback

    def _process_message(self, message):
        """Process a single message"""
        try:
            topic = message.topic
            value = message.value

            if not value:
                return

            self.stats['last_message_time'] = datetime.now()
            
            if topic in self.config.topics_flows and self.flow_callback:
                self.flow_callback(value)
                self.stats['messages_processed'] += 1
            elif topic in self.config.topics_alerts and self.alert_callback:
                self.alert_callback(value)
                self.stats['messages_processed'] += 1
            elif topic in self.config.topics_metrics and self.metric_callback:
                self.metric_callback(value)
                self.stats['messages_processed'] += 1
            elif topic in self.config.topics_mitigation and self.mitigation_callback:
                self.mitigation_callback(value)
                self.stats['messages_processed'] += 1

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.stats['errors'] += 1

    def consume_forever(self):
        """Consume messages forever (blocking)"""
        logger.info("Starting infinite consumption loop")

        while self.is_running and self.consumer:
            try:
                messages = self.consumer.poll(timeout_ms=1000)

                if not messages:
                    continue

                for topic_partition, records in messages.items():
                    for record in records:
                        self._process_message(record)
                        self.stats['messages_consumed'] += 1

                    if not self.config.enable_auto_commit:
                        self.consumer.commit()

            except Exception as e:
                logger.error(f"Error in consume loop: {e}")
                self.stats['errors'] += 1
                if self.is_running:
                    import time
                    time.sleep(1)

        logger.info("Consumption loop ended")

    async def consume_async(self, max_messages: Optional[int] = None):
        """Consume messages asynchronously"""
        loop = asyncio.get_event_loop()
        messages_consumed = 0

        while self.is_running and (max_messages is None or messages_consumed < max_messages):
            try:
                messages = await loop.run_in_executor(
                    self._processing_thread_pool,
                    lambda: self.consumer.poll(timeout_ms=1000) if self.consumer else {}
                )

                if not messages:
                    await asyncio.sleep(0.01)
                    continue

                for topic_partition, records in messages.items():
                    for record in records:
                        await loop.run_in_executor(
                            self._processing_thread_pool,
                            self._process_message,
                            record
                        )
                        messages_consumed += 1
                        self.stats['messages_consumed'] += 1

                    if not self.config.enable_auto_commit:
                        await loop.run_in_executor(None, self.consumer.commit)

            except Exception as e:
                logger.error(f"Error in async consume: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(1)

    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics"""
        return {
            **self.stats, 
            'is_running': self.is_running, 
            'group_id': self.config.group_id,
            'subscribed_topics': self.config.topics_flows + self.config.topics_alerts,
        }


class DetectionConsumer(FlowConsumer):
    """Extended consumer with built-in detection capabilities"""
    
    def __init__(self, config: ConsumerConfig, window_aggregator=None):
        super().__init__(config)
        self.window_aggregator = window_aggregator
        self.detection_callback: Optional[Callable] = None

    def process_with_detection(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process flow with window aggregation and detection"""
        if self.window_aggregator:
            try:
                aggregated = self.window_aggregator.add_flow(flow)
                if aggregated:
                    # Check for anomalies in the aggregated stats
                    is_anomaly = aggregated.get('is_anomaly_packet_rate', False)
                    if is_anomaly:
                        aggregated['detection_type'] = 'packet_rate_anomaly'
                        aggregated['detection_timestamp'] = datetime.utcnow().isoformat()
                        return aggregated
                return None
            except Exception as e:
                logger.error(f"Error in detection processing: {e}")
                return None
        return None

    def register_detection_callback(self, callback: Callable):
        """Register callback for detection results"""
        self.detection_callback = callback
        
        # Wrap the flow callback to trigger detection
        def detection_wrapper(flow):
            result = self.process_with_detection(flow)
            if result and self.detection_callback:
                self.detection_callback(result)
                
        self.register_flow_callback(detection_wrapper)


def _run_flow_consumer() -> None:
    """Entry point for running the consumer as a standalone script"""
    import os
    import signal

    # Configure logging
    level = getattr(
        logging,
        os.environ.get("LOG_LEVEL", "INFO").upper(),
        logging.INFO,
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Parse configuration from environment
    reset_raw = os.environ.get("KAFKA_AUTO_OFFSET_RESET", "earliest").lower()
    offset = (
        AutoOffsetReset.LATEST
        if reset_raw == "latest"
        else AutoOffsetReset.EARLIEST
    )

    config = ConsumerConfig(
        bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        group_id=os.environ.get("KAFKA_GROUP_ID", "ddos-detection-group"),
        auto_offset_reset=offset,
        enable_auto_commit=os.environ.get("KAFKA_ENABLE_AUTO_COMMIT", "true").lower()
        in ("1", "true", "yes"),
    )
    
    consumer = FlowConsumer(config)

    def shutdown(*_args: object) -> None:
        logger.info("Shutting down...")
        consumer.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    consumer.start()
    try:
        consumer.consume_forever()
    finally:
        consumer.stop()


if __name__ == "__main__":
    _run_flow_consumer()
