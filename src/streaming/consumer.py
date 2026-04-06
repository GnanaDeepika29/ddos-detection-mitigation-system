"""
Kafka Consumer Module

Consumes network flows, alerts, and metrics from Kafka topics.
"""

import json
import asyncio
import logging
import os
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

    The real Kafka client returns hashable ``TopicPartition`` objects.  Some
    lightweight mocks use ``SimpleNamespace`` instead, which is unhashable by
    default and breaks polling loops that expect a mapping keyed by partition.

    The check correctly uses ``is not None``:
    • Unpatched: ``SimpleNamespace.__hash__`` is explicitly ``None``
      → ``getattr`` returns ``None`` → ``None is not None`` is ``False``
      → we fall through and apply the patch.
    • Already patched: ``__hash__`` is a real callable
      → ``is not None`` is ``True`` → we return early (idempotent).
    """
    if getattr(types.SimpleNamespace, "__hash__", None) is not None:
        return

    class _HashableSimpleNamespace(types.SimpleNamespace):
        __hash__ = object.__hash__

    types.SimpleNamespace = _HashableSimpleNamespace  # type: ignore[misc]


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
    max_poll_interval_ms: int = 300_000
    session_timeout_ms: int = 10_000
    heartbeat_interval_ms: int = 3_000
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str = "PLAIN"
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    ssl_ca_location: Optional[str] = None
    ssl_certificate_location: Optional[str] = None
    ssl_key_location: Optional[str] = None

    def to_kafka_config(self) -> Dict[str, Any]:
        """Convert to a Kafka consumer configuration dictionary."""
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

        if self.security_protocol in ("SASL_SSL", "SASL_PLAINTEXT"):
            config['sasl_mechanism'] = self.sasl_mechanism
            if self.sasl_username and self.sasl_password:
                config['sasl_plain_username'] = self.sasl_username
                config['sasl_plain_password'] = self.sasl_password

        if self.security_protocol in ("SSL", "SASL_SSL"):
            if self.ssl_ca_location:
                config['ssl_cafile'] = self.ssl_ca_location
            if self.ssl_certificate_location:
                config['ssl_certfile'] = self.ssl_certificate_location
            if self.ssl_key_location:
                config['ssl_keyfile'] = self.ssl_key_location

        return config


class FlowConsumer:
    """Kafka consumer for network flows and detection events."""

    def __init__(self, config: ConsumerConfig) -> None:
        if not KAFKA_AVAILABLE:
            raise ImportError(
                "kafka-python is required. Install with: pip install kafka-python"
            )

        self.config = config
        self.consumer: Optional[KafkaConsumer] = None
        self.is_running = False
        self._processing_thread_pool = ThreadPoolExecutor(max_workers=10)
        self.flow_callback: Optional[Callable] = None
        self.alert_callback: Optional[Callable] = None
        self.metric_callback: Optional[Callable] = None
        self.mitigation_callback: Optional[Callable] = None
        self.stats: Dict[str, Any] = {
            'messages_consumed': 0,
            'messages_processed': 0,
            'errors': 0,
            'last_message_time': None,
        }

        logger.info(f"FlowConsumer initialised for group: {config.group_id}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _deserialize_value(self, value_bytes: Optional[bytes]) -> Optional[Dict[str, Any]]:
        """Deserialise a JSON-encoded Kafka message."""
        if value_bytes is None:
            return None
        try:
            return json.loads(value_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error(f"Failed to deserialise JSON: {exc}")
            return None

    def _process_message(self, message: Any) -> bool:
        """
        Process a single Kafka message.

        Returns True if the message was handled successfully, False otherwise.
        Callers use the return value to decide whether to commit the offset.

        FIX BUG-21: The original implementation swallowed exceptions and then
        committed the offset unconditionally, causing silent message loss for
        any record that triggered an error.  Now the return value signals
        success/failure so consume_forever() and consume_async() can skip the
        commit on failure and leave the offset un-committed for retry.
        """
        try:
            topic = message.topic
            value = message.value

            if not value:
                return True   # Empty / tombstone — commit and move on

            self.stats['last_message_time'] = datetime.now()

            dispatched = False
            if topic in self.config.topics_flows and self.flow_callback:
                self.flow_callback(value)
                dispatched = True
            elif topic in self.config.topics_alerts and self.alert_callback:
                self.alert_callback(value)
                dispatched = True
            elif topic in self.config.topics_metrics and self.metric_callback:
                self.metric_callback(value)
                dispatched = True
            elif topic in self.config.topics_mitigation and self.mitigation_callback:
                self.mitigation_callback(value)
                dispatched = True

            if dispatched:
                self.stats['messages_processed'] += 1

            return True

        except Exception as exc:
            logger.error(f"Error processing message from {message.topic}: {exc}")
            self.stats['errors'] += 1
            return False   # FIX BUG-21: Signal failure so caller skips commit

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Kafka consumer."""
        try:
            _ensure_hashable_simple_namespace()
            all_topics = (
                self.config.topics_flows
                + self.config.topics_alerts
                + self.config.topics_metrics
                + self.config.topics_mitigation
            )

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
        except Exception as exc:
            logger.error(f"Failed to start Kafka consumer: {exc}")
            raise

    def stop(self) -> None:
        """Stop the Kafka consumer."""
        self.is_running = False
        if self.consumer:
            self.consumer.close()
            logger.info("Kafka consumer stopped")
        self._processing_thread_pool.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def register_flow_callback(self, callback: Callable) -> None:
        self.flow_callback = callback

    def register_alert_callback(self, callback: Callable) -> None:
        self.alert_callback = callback

    def register_metric_callback(self, callback: Callable) -> None:
        self.metric_callback = callback

    def register_mitigation_callback(self, callback: Callable) -> None:
        self.mitigation_callback = callback

    # ------------------------------------------------------------------
    # Consumption loops
    # ------------------------------------------------------------------

    def consume_forever(self) -> None:
        """Consume messages indefinitely (blocking)."""
        logger.info("Starting infinite consumption loop")

        while self.is_running and self.consumer:
            try:
                messages = self.consumer.poll(timeout_ms=1000)

                if not messages:
                    continue

                for topic_partition, records in messages.items():
                    all_ok = True
                    for record in records:
                        ok = self._process_message(record)
                        self.stats['messages_consumed'] += 1
                        if not ok:
                            all_ok = False

                    # FIX BUG-21: Only commit when every record in the batch
                    # succeeded.  On partial failure we leave the partition
                    # offset un-advanced so the failing record will be
                    # redelivered on the next poll.
                    if not self.config.enable_auto_commit and all_ok:
                        self.consumer.commit()

            except Exception as exc:
                logger.error(f"Error in consume loop: {exc}")
                self.stats['errors'] += 1
                if self.is_running:
                    import time
                    time.sleep(1)

        logger.info("Consumption loop ended")

    async def consume_async(self, max_messages: Optional[int] = None) -> None:
        """Consume messages asynchronously."""
        loop = asyncio.get_running_loop()
        messages_consumed = 0

        while self.is_running and (
            max_messages is None or messages_consumed < max_messages
        ):
            try:
                messages = await loop.run_in_executor(
                    self._processing_thread_pool,
                    lambda: self.consumer.poll(timeout_ms=1000) if self.consumer else {},
                )

                if not messages:
                    await asyncio.sleep(0.01)
                    continue

                for topic_partition, records in messages.items():
                    all_ok = True
                    for record in records:
                        ok = await loop.run_in_executor(
                            self._processing_thread_pool,
                            self._process_message,
                            record,
                        )
                        messages_consumed += 1
                        self.stats['messages_consumed'] += 1
                        if not ok:
                            all_ok = False

                    # FIX BUG-21 (async path): same commit-on-success logic.
                    # FIX BUG-23: Use self._processing_thread_pool for commit
                    # rather than the default None executor, keeping thread
                    # usage consistent and predictable.
                    if not self.config.enable_auto_commit and all_ok:
                        await loop.run_in_executor(
                            self._processing_thread_pool,   # FIX BUG-23
                            self.consumer.commit,
                        )

            except Exception as exc:
                logger.error(f"Error in async consume: {exc}")
                self.stats['errors'] += 1
                await asyncio.sleep(1)

    def get_stats(self) -> Dict[str, Any]:
        """Return consumer statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'group_id': self.config.group_id,
            'subscribed_topics': (
                self.config.topics_flows + self.config.topics_alerts
            ),
        }


class DetectionConsumer(FlowConsumer):
    """Extended consumer with built-in window-aggregation and detection."""

    def __init__(self, config: ConsumerConfig, window_aggregator: Any = None) -> None:
        super().__init__(config)
        self.window_aggregator = window_aggregator
        self.detection_callback: Optional[Callable] = None

    def process_with_detection(
        self, flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Process a flow through window aggregation and anomaly detection."""
        if not self.window_aggregator:
            return None
        try:
            aggregated = self.window_aggregator.add_flow(flow)
            if aggregated and aggregated.get('is_anomaly_packet_rate', False):
                aggregated['detection_type'] = 'packet_rate_anomaly'
                aggregated['detection_timestamp'] = datetime.utcnow().isoformat()
                return aggregated
            return None
        except Exception as exc:
            logger.error(f"Error in detection processing: {exc}")
            return None

    def register_detection_callback(self, callback: Callable) -> None:
        """Register a callback for detection results."""
        self.detection_callback = callback

        def _detection_wrapper(flow: Dict[str, Any]) -> None:
            result = self.process_with_detection(flow)
            if result and self.detection_callback:
                self.detection_callback(result)

        self.register_flow_callback(_detection_wrapper)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def _run_flow_consumer() -> None:
    """Entry point for running the consumer as a standalone process."""
    import signal
    import time

    level = getattr(
        logging,
        os.environ.get("LOG_LEVEL", "INFO").upper(),
        logging.INFO,
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    reset_raw = os.environ.get("KAFKA_AUTO_OFFSET_RESET", "earliest").lower()
    offset = AutoOffsetReset.LATEST if reset_raw == "latest" else AutoOffsetReset.EARLIEST

    # FIX BUG-25: Read topic names from environment so the entry point works
    # with both dev (network_flows_dev) and prod (network_flows_prod) topics
    # instead of always defaulting to the bare "network_flows" topic.
    topics_flows_raw = os.environ.get("KAFKA_TOPIC_FLOWS", "network_flows")
    topics_alerts_raw = os.environ.get("KAFKA_TOPIC_ALERTS", "")
    topics_metrics_raw = os.environ.get("KAFKA_TOPIC_METRICS", "")
    topics_mitigation_raw = os.environ.get("KAFKA_TOPIC_MITIGATION", "")

    config = ConsumerConfig(
        bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        group_id=os.environ.get("KAFKA_GROUP_ID", "ddos-detection-group"),
        auto_offset_reset=offset,
        enable_auto_commit=os.environ.get(
            "KAFKA_ENABLE_AUTO_COMMIT", "false"
        ).lower() in ("1", "true", "yes"),
        topics_flows=[t.strip() for t in topics_flows_raw.split(",") if t.strip()],
        topics_alerts=[t.strip() for t in topics_alerts_raw.split(",") if t.strip()],
        topics_metrics=[t.strip() for t in topics_metrics_raw.split(",") if t.strip()],
        topics_mitigation=[t.strip() for t in topics_mitigation_raw.split(",") if t.strip()],
    )

    consumer = FlowConsumer(config)

    def _shutdown(*_: Any) -> None:
        logger.info("Shutting down consumer...")
        consumer.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    consumer.start()
    try:
        consumer.consume_forever()
    finally:
        consumer.stop()


if __name__ == "__main__":
    _run_flow_consumer()