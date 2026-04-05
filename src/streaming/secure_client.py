"""
Secure Kafka and Redis Client

Provides SSL/TLS enabled clients for Kafka and Redis with strong security defaults.
"""

import ssl
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

try:
    from kafka import KafkaProducer, KafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class SecureClientConfig:
    """Configuration for secure clients"""
    brokers: str = "localhost:9092"
    username: Optional[str] = None
    password: Optional[str] = None
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    tls_verify: bool = True
    sasl_mechanism: str = "SCRAM-SHA-512"


class SecureKafkaClient:
    """Secure Kafka client with SSL/TLS and SASL support"""
    
    def __init__(self, config: SecureClientConfig):
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required for Kafka client")
            
        self.config = config
        self.ssl_context = self._create_ssl_context()
        
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with security hardening"""
        context = ssl.create_default_context()
        
        if self.config.tls_verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("TLS verification disabled - not recommended for production")
        
        # Load CA certificate if provided
        if self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
        
        # Load client certificate if provided
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(
                self.config.client_cert_path, 
                self.config.client_key_path
            )
        
        # Enforce strong TLS versions
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Set secure cipher suites
        context.set_ciphers(
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
        )
        
        return context
    
    def get_producer(self, **kwargs) -> KafkaProducer:
        """Get secure Kafka producer"""
        config = {
            'bootstrap_servers': self.config.brokers,
            'security_protocol': 'SSL' if not self.config.username else 'SASL_SSL',
            'ssl_context': self.ssl_context,
            **kwargs
        }
        
        if self.config.username and self.config.password:
            config.update({
                'sasl_mechanism': self.config.sasl_mechanism,
                'sasl_plain_username': self.config.username,
                'sasl_plain_password': self.config.password,
            })
        
        return KafkaProducer(**config)
    
    def get_consumer(self, group_id: str, **kwargs) -> KafkaConsumer:
        """Get secure Kafka consumer"""
        config = {
            'bootstrap_servers': self.config.brokers,
            'group_id': group_id,
            'security_protocol': 'SSL' if not self.config.username else 'SASL_SSL',
            'ssl_context': self.ssl_context,
            **kwargs
        }
        
        if self.config.username and self.config.password:
            config.update({
                'sasl_mechanism': self.config.sasl_mechanism,
                'sasl_plain_username': self.config.username,
                'sasl_plain_password': self.config.password,
            })
        
        return KafkaConsumer(**config)


class SecureRedisClient:
    """Secure Redis client with SSL/TLS support"""
    
    def __init__(
        self, 
        host: str, 
        port: int, 
        password: str, 
        use_tls: bool = True,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None
    ):
        if not REDIS_AVAILABLE:
            raise ImportError("redis is required. Install with: pip install redis")
            
        self.host = host
        self.port = port
        self.password = password
        self.use_tls = use_tls
        
        self.client = self._create_client(
            ca_cert_path, client_cert_path, client_key_path
        )
    
    def _create_client(
        self,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None
    ) -> redis.Redis:
        """Create Redis client with security settings"""
        config = {
            'host': self.host,
            'port': self.port,
            'password': self.password,
            'decode_responses': True,
            'socket_timeout': 5,
            'socket_connect_timeout': 5,
            'retry_on_timeout': True,
        }
        
        if self.use_tls:
            config.update({
                'ssl': True,
                'ssl_cert_reqs': 'required' if ca_cert_path else 'none',
                'ssl_check_hostname': bool(ca_cert_path),
            })
            
            if ca_cert_path:
                config['ssl_ca_certs'] = ca_cert_path
            if client_cert_path:
                config['ssl_certfile'] = client_cert_path
            if client_key_path:
                config['ssl_keyfile'] = client_key_path
        
        return redis.Redis(**config)
    
    def get_client(self) -> redis.Redis:
        """Get the Redis client"""
        return self.client
    
    def ping(self) -> bool:
        """Test connection"""
        try:
            return self.client.ping()
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False
    
    def close(self):
        """Close the connection"""
        self.client.close()


def create_secure_clients_from_env() -> Dict[str, Any]:
    """Create secure clients from environment variables"""
    import os
    
    config = SecureClientConfig(
        brokers=os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
        username=os.environ.get('KAFKA_SASL_USERNAME'),
        password=os.environ.get('KAFKA_SASL_PASSWORD'),
        ca_cert_path=os.environ.get('KAFKA_SSL_CA_LOCATION'),
        client_cert_path=os.environ.get('KAFKA_SSL_CERTIFICATE_LOCATION'),
        client_key_path=os.environ.get('KAFKA_SSL_KEY_LOCATION'),
        tls_verify=os.environ.get('KAFKA_SSL_VERIFY', 'true').lower() == 'true',
        sasl_mechanism=os.environ.get('KAFKA_SASL_MECHANISM', 'SCRAM-SHA-512'),
    )
    
    kafka_client = SecureKafkaClient(config)
    
    redis_client = None
    if REDIS_AVAILABLE and os.environ.get('REDIS_HOST'):
        redis_client = SecureRedisClient(
            host=os.environ.get('REDIS_HOST', 'localhost'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            password=os.environ.get('REDIS_PASSWORD', ''),
            use_tls=os.environ.get('REDIS_TLS_ENABLED', 'false').lower() == 'true',
            ca_cert_path=os.environ.get('REDIS_CA_CERT'),
            client_cert_path=os.environ.get('REDIS_CLIENT_CERT'),
            client_key_path=os.environ.get('REDIS_CLIENT_KEY'),
        )
    
    return {
        'kafka': kafka_client,
        'redis': redis_client,
    }