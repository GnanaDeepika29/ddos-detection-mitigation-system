"""
Kafka Producer Module

Publishes network flows and detection events to Kafka topics.
"""

import json
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logging.warning("kafka-python not available. Install with: pip install kafka-python")

logger = logging.getLogger(__name__)


class CompressionType(Enum):
    """Compression types for Kafka messages"""
    NONE = 'none'
    GZIP = 'gzip'
    SNAPPY = 'snappy'
    LZ4 = 'lz4'


@dataclass
class ProducerConfig:
    """Configuration for Kafka producer"""
    bootstrap_servers: str = "localhost:9092"
    client_id: str = "ddos-flow-producer"
    topic_flows: str = "network_flows"
    topic_alerts: str = "ddos_alerts"
    topic_metrics: str = "detection_metrics"
    topic_mitigation: str = "mitigation_events"
    batch_size: int = 16384
    linger_ms: int = 5
    compression_type: CompressionType = CompressionType.SNAPPY
    max_request_size: int = 1048576
    buffer_memory: int = 33554432
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
        """Convert to Kafka producer configuration dictionary"""
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required for Kafka producer")
            
        config: Dict[str, Any] = {
            'bootstrap_servers': self.bootstrap_servers,
            'client_id': self.client_id,
            'batch_size': self.batch_size,
            'linger_ms': self.linger_ms,
            'max_request_size': self.max_request_size,
            'buffer_memory': self.buffer_memory,
            'acks': 'all' if self.enable_idempotence else self.acks,
            'retries': self.retries,
            'enable_idempotence': self.enable_idempotence,
        }

        if self.compression_type != CompressionType.NONE:
            config['compression_type'] = self.compression_type.value

        if self.security_protocol != "PLAINTEXT":
            config['security_protocol'] = self.security_protocol
            
            if self.security_protocol == "SASL_SSL" or self.security_protocol == "SASL_PLAINTEXT":
                config['sasl_mechanism'] = self.sasl_mechanism
                if self.sasl_username and self.sasl_password:
                    config['sasl_plain_username'] = self.sasl_username
                    config['sasl_plain_password'] = self.sasl_password
                    
            if self.security_protocol == "SSL" or self.security_protocol == "SASL_SSL":
                if self.ssl_ca_location:
                    config['ssl_cafile'] = self.ssl_ca_location
                if self.ssl_certificate_location:
                    config['ssl_certfile'] = self.ssl_certificate_location
                if self.ssl_key_location:
                    config['ssl_keyfile'] = self.ssl_key_location

        return config


class FlowProducer:
    """Kafka producer for network flows and detection events"""
    
    def __init__(self, config: ProducerConfig):
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required. Install with: pip install kafka-python")
            
        self.config = config
        self.producer: Optional[KafkaProducer] = None
        self.is_running = False
        self.stats = {'messages_sent': 0, 'bytes_sent': 0, 'errors': 0}

        logger.info(f"FlowProducer initialized with config: {config.bootstrap_servers}")

    def _estimate_payload_size(self, value: Dict[str, Any]) -> int:
        """Estimate serialized payload size for producer statistics."""
        return len(self._serialize_value(value))

    def _serialize_value(self, value: Dict[str, Any]) -> bytes:
        """Serialize dictionary to JSON bytes"""
        out = {}
        for k, v in value.items():
            if isinstance(v, datetime):
                out[k] = v.isoformat()
            elif isinstance(v, float):
                out[k] = round(v, 6)
            else:
                out[k] = v

        out['_producer_timestamp'] = datetime.utcnow().isoformat()
        return json.dumps(out, default=str).encode('utf-8')

    def start(self):
        """Start the Kafka producer"""
        try:
            config = self.config.to_kafka_config()
            self.producer = KafkaProducer(
                **config,
                value_serializer=self._serialize_value,
            )
            self.is_running = True
            logger.info(f"Kafka producer started, connected to {self.config.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to start Kafka producer: {e}")
            raise

    def stop(self):
        """Stop the Kafka producer"""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            self.is_running = False
            logger.info("Kafka producer stopped")

    def flush(self):
        """Flush any pending messages"""
        if self.producer:
            self.producer.flush()

    def send_flow(self, flow: Dict[str, Any], key: Optional[str] = None) -> bool:
        """Send a flow message to Kafka"""
        if not self.is_running or not self.producer:
            logger.warning("Producer not running")
            return False

        try:
            if key is None:
                key = flow.get('flow_id', flow.get('ip_src', 'unknown'))

            self.stats['bytes_sent'] += self._estimate_payload_size(flow)

            future = self.producer.send(
                self.config.topic_flows, 
                key=key.encode('utf-8') if key else None, 
                value=flow
            )
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True

        except Exception as e:
            logger.error(f"Failed to send flow to Kafka: {e}")
            self.stats['errors'] += 1
            return False

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send an alert message to Kafka"""
        if not self.is_running or not self.producer:
            return False

        try:
            alert['alert_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(alert)
            future = self.producer.send(self.config.topic_alerts, value=alert)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as e:
            logger.error(f"Failed to send alert to Kafka: {e}")
            self.stats['errors'] += 1
            return False

    def send_metric(self, metric: Dict[str, Any]) -> bool:
        """Send a metric message to Kafka"""
        if not self.is_running or not self.producer:
            return False

        try:
            metric['metric_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(metric)
            future = self.producer.send(self.config.topic_metrics, value=metric)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as e:
            logger.error(f"Failed to send metric to Kafka: {e}")
            self.stats['errors'] += 1
            return False

    def send_mitigation(self, mitigation: Dict[str, Any]) -> bool:
        """Send a mitigation event to Kafka"""
        if not self.is_running or not self.producer:
            return False

        try:
            mitigation['mitigation_timestamp'] = datetime.utcnow().isoformat()
            self.stats['bytes_sent'] += self._estimate_payload_size(mitigation)
            future = self.producer.send(self.config.topic_mitigation, value=mitigation)
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            return True
        except Exception as e:
            logger.error(f"Failed to send mitigation to Kafka: {e}")
            self.stats['errors'] += 1
            return False

    def _on_send_success(self, record_metadata):
        """Callback for successful message send"""
        self.stats['messages_sent'] += 1
        if self.stats['messages_sent'] % 1000 == 0:
            logger.debug(f"Sent {self.stats['messages_sent']} messages")

    def _on_send_error(self, error):
        """Callback for failed message send"""
        logger.error(f"Failed to send message to Kafka: {error}")
        self.stats['errors'] += 1

    async def send_batch(self, flows: List[Dict[str, Any]], batch_size: int = 100):
        """Send a batch of flows asynchronously"""
        for i in range(0, len(flows), batch_size):
            batch = flows[i:i + batch_size]
            for flow in batch:
                self.send_flow(flow)
            await asyncio.sleep(0.01)

    def get_stats(self) -> Dict[str, Any]:
        """Get producer statistics"""
        return {
            **self.stats,
            'is_running': self.is_running,
            'bootstrap_servers': self.config.bootstrap_servers,
            'topic_flows': self.config.topic_flows,
        }


class FlowProducerFactory:
    """Factory for creating FlowProducer instances"""
    
    @staticmethod
    def create_local_producer() -> FlowProducer:
        """Create a producer for local development"""
        config = ProducerConfig(
            bootstrap_servers="localhost:9092",
            enable_idempotence=False
        )
        return FlowProducer(config)

    @staticmethod
    def create_production_producer(servers: str, security_config: Optional[Dict] = None) -> FlowProducer:
        """Create a producer for production environment"""
        config = ProducerConfig(
            bootstrap_servers=servers,
            acks='all',
            enable_idempotence=True,
            security_protocol=security_config.get('security_protocol', 'PLAINTEXT') if security_config else 'PLAINTEXT',
            sasl_username=security_config.get('sasl_username') if security_config else None,
            sasl_password=security_config.get('sasl_password') if security_config else None,
            ssl_ca_location=security_config.get('ssl_ca_location') if security_config else None,
            ssl_certificate_location=security_config.get('ssl_certificate_location') if security_config else None,
            ssl_key_location=security_config.get('ssl_key_location') if security_config else None,
        )
        return FlowProducer(config)

    @staticmethod
    def create_cloud_producer(cloud_provider: str, config: Dict) -> FlowProducer:
        """Create a producer for cloud environments"""
        if cloud_provider == 'aws':
            # For AWS MSK with IAM auth
            config = ProducerConfig(
                bootstrap_servers=config['bootstrap_servers'],
                security_protocol='SASL_SSL',
                sasl_mechanism='AWS_MSK_IAM',
                sasl_username=config.get('aws_access_key'),
                sasl_password=config.get('aws_secret_key'),
            )
        elif cloud_provider == 'confluent':
            # For Confluent Cloud
            config = ProducerConfig(
                bootstrap_servers=config['bootstrap_servers'],
                security_protocol='SASL_SSL',
                sasl_mechanism='PLAIN',
                sasl_username=config['api_key'],
                sasl_password=config['api_secret'],
            )
        else:
            config = ProducerConfig(bootstrap_servers=config['bootstrap_servers'])
            
        return FlowProducer(config)
