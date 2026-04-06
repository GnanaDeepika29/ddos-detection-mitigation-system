"""
Kafka Producer Module

Publishes network flows and detection events to Kafka topics.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logging.warning("kafka-python not available. Install with: pip install kafka-python")

logger = logging.getLogger(__name__)


class CompressionType(Enum):
    """Compression types for Kafka messages."""
    NONE = 'none'
    GZIP = 'gzip'
    SNAPPY = 'snappy'
    LZ4 = 'lz4'
    # FIX BUG-29: prod.yaml specifies compression: "zstd" but this enum
    # previously had no ZSTD entry, causing a lookup error at runtime.
    ZSTD = 'zstd'


@dataclass
class ProducerConfig:
    """Configuration for Kafka producer."""
    bootstrap_servers: str = "localhost:9092"
    client_id: str = "ddos-flow-producer"
    topic_flows: str = "network_flows"
    topic_alerts: str = "ddos_alerts"
    topic_metrics: str = "detection_metrics"
    topic_mitigation: str = "mitigation_events"
    batch_size: int = 16_384
    linger_ms: int = 5
    compression_type: CompressionType = CompressionType.SNAPPY
    max_request_size: int = 1_048_576
    buffer_memory: int = 33_554_432
    acks: Union[int, str] = 1
    retries: int = 3
    enable_idempotence: bool = True
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str = "PLAIN"
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    ssl_ca_location: Optional[str] = None
    ssl_certificate_location: Optional[str] = None
    ssl_key_location: Optional[str] = None

    def to_kafka_config(self) -> Dict[str, Any]:
        """Convert to a Kafka producer configuration dictionary."""
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required for Kafka producer")

        config: Dict[str, Any] = {
            'bootstrap_servers': self.bootstrap_servers,
            'client_id': self.client_id,
            'batch_size': self.batch_size,
            'linger_ms': self.linger_ms,
            'max_request_size': self.max_request_size,
            'buffer_memory': self.buffer_memory,
            # When idempotence is on, Kafka requires acks='all'
            'acks': 'all' if self.enable_idempotence else self.acks,
            'retries': self.retries,
            'enable_idempotence': self.enable_idempotence,
        }

        if self.compression_type != CompressionType.NONE:
            config['compression_type'] = self.compression_type.value

        if self.security_protocol != "PLAINTEXT":
            config['security_protocol'] = self.security_protocol

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


class FlowProducer:
    """Kafka producer for network flows and detection events."""

    def __init__(self, config: ProducerConfig) -> None:
        if not KAFKA_AVAILABLE:
            raise ImportError(
                "kafka-python is required. Install with: pip install kafka-python"
            )

        self.config = config
        self.producer: Optional[KafkaProducer] = None
        self.is_running = False
        self.stats: Dict[str, Any] = {
            'messages_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
        }

        logger.info(f"FlowProducer initialised: {config.bootstrap_servers}")

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _serialize_value(self, value: Dict[str, Any]) -> bytes:
        """Serialise a dictionary to JSON bytes, normalising datetime values."""
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(v, datetime):
                out[k] = v.isoformat()
            elif isinstance(v, float):
                out[k] = round(v, 6)
            else:
                out[k] = v
        out['_producer_timestamp'] = datetime.utcnow().isoformat()
        return json.dumps(out, default=str).encode('utf-8')

    def _estimate_payload_size(self, value: Dict[str, Any]) -> int:
        """Estimate serialised payload size for producer statistics."""
        return len(self._serialize_value(value))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Kafka producer."""
        try:
            config = self.config.to_kafka_config()
            self.producer = KafkaProducer(
                **config,
                value_serializer=self._serialize_value,
            )
            self.is_running = True
            logger.info(
                f"Kafka producer started, connected to {self.config.bootstrap_servers}"
            )
        except Exception as exc:
            logger.error(f"Failed to start Kafka producer: {exc}")
            raise

    def stop(self) -> None:
        """Flush pending messages and close the producer."""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            self.is_running = False
            logger.info("Kafka producer stopped")

    def flush(self) -> None:
        """Flush any pending messages."""
        if self.producer:
            self.producer.flush()

    # ------------------------------------------------------------------
    # Send helpers
    # ------------------------------------------------------------------

    def send_flow(self, flow: Dict[str, Any], key: Optional[str] = None) -> bool:
        """Send a flow record to the flows topic."""
        if not self.is_running or not self.producer:
            logger.warning("Producer not running — flow dropped")
            return False

        try:
            if key is None:
                key = flow.get('flow_id') or flow.get('ip_src', 'unknown')

            self.stats['bytes_sent'] += self._estimate_payload_size(flow)
            future = self.producer.send(
                self.config.topic_flows,
                key=key.encode('utf-8') if key else None,
                value=flow,
            )
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as exc:
            logger.error(f"Failed to send flow to Kafka: {exc}")
            self.stats['errors'] += 1
            return False

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send an alert record to the alerts topic."""
        if not self.is_running or not self.producer:
            return False
        try:
            alert['alert_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(alert)
            future = self.producer.send(self.config.topic_alerts, value=alert)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as exc:
            logger.error(f"Failed to send alert to Kafka: {exc}")
            self.stats['errors'] += 1
            return False

    def send_metric(self, metric: Dict[str, Any]) -> bool:
        """Send a metric record to the metrics topic."""
        if not self.is_running or not self.producer:
            return False
        try:
            metric['metric_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(metric)
            future = self.producer.send(self.config.topic_metrics, value=metric)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as exc:
            logger.error(f"Failed to send metric to Kafka: {exc}")
            self.stats['errors'] += 1
            return False

    def send_mitigation(self, mitigation: Dict[str, Any]) -> bool:
        """Send a mitigation event to the mitigation topic."""
        if not self.is_running or not self.producer:
            return False
        try:
            mitigation['mitigation_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(mitigation)
            future = self.producer.send(self.config.topic_mitigation, value=mitigation)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as exc:
            logger.error(f"Failed to send mitigation to Kafka: {exc}")
            self.stats['errors'] += 1
            return False

    def _on_send_success(self, record_metadata: Any) -> None:
        self.stats['messages_sent'] += 1
        if self.stats['messages_sent'] % 1000 == 0:
            logger.debug(f"Sent {self.stats['messages_sent']:,} messages total")

    def _on_send_error(self, error: Exception) -> None:
        logger.error(f"Failed to send message to Kafka: {error}")
        self.stats['errors'] += 1

    async def send_batch(
        self, flows: List[Dict[str, Any]], batch_size: int = 100
    ) -> None:
        """Send a batch of flows asynchronously with small inter-batch yields."""
        for i in range(0, len(flows), batch_size):
            for flow in flows[i: i + batch_size]:
                self.send_flow(flow)
            await asyncio.sleep(0.01)

    def get_stats(self) -> Dict[str, Any]:
        """Return producer statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'bootstrap_servers': self.config.bootstrap_servers,
            'topic_flows': self.config.topic_flows,
        }


class FlowProducerFactory:
    """Factory for creating FlowProducer instances."""

    @staticmethod
    def create_local_producer() -> FlowProducer:
        """Create a producer for local development."""
        config = ProducerConfig(
            bootstrap_servers="localhost:9092",
            enable_idempotence=False,
        )
        return FlowProducer(config)

    @staticmethod
    def create_production_producer(
        servers: str,
        security_config: Optional[Dict[str, Any]] = None,
    ) -> FlowProducer:
        """Create a producer for the production environment."""
        sc = security_config or {}
        config = ProducerConfig(
            bootstrap_servers=servers,
            acks='all',
            enable_idempotence=True,
            security_protocol=sc.get('security_protocol', 'PLAINTEXT'),
            sasl_username=sc.get('sasl_username'),
            sasl_password=sc.get('sasl_password'),
            ssl_ca_location=sc.get('ssl_ca_location'),
            ssl_certificate_location=sc.get('ssl_certificate_location'),
            ssl_key_location=sc.get('ssl_key_location'),
        )
        return FlowProducer(config)

    @staticmethod
    def create_cloud_producer(cloud_provider: str, config: Dict[str, Any]) -> FlowProducer:
        """
        Create a producer for cloud environments.

        FIX BUG-28: The original code reused the name ``config`` for both the
        incoming ``Dict`` parameter and the ``ProducerConfig`` instance built
        inside each branch.  This shadowed the parameter, making the code
        fragile (any new branch that forgot to reassign ``config`` would call
        ``FlowProducer(dict)`` and crash at runtime).  Renamed the local
        variable to ``producer_config`` to make the intent explicit.
        """
        if cloud_provider == 'aws':
            # AWS MSK with IAM auth
            producer_config = ProducerConfig(
                bootstrap_servers=config['bootstrap_servers'],
                security_protocol='SASL_SSL',
                sasl_mechanism='AWS_MSK_IAM',
                sasl_username=config.get('aws_access_key'),
                sasl_password=config.get('aws_secret_key'),
            )
        elif cloud_provider == 'confluent':
            # Confluent Cloud
            producer_config = ProducerConfig(
                bootstrap_servers=config['bootstrap_servers'],
                security_protocol='SASL_SSL',
                sasl_mechanism='PLAIN',
                sasl_username=config['api_key'],
                sasl_password=config['api_secret'],
            )
        else:
            producer_config = ProducerConfig(
                bootstrap_servers=config['bootstrap_servers'],
            )

        return FlowProducer(producer_config)