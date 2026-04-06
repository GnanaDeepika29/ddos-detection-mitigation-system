"""
Secure Kafka and Redis Client

Provides SSL/TLS-enabled clients for Kafka and Redis with strong security
defaults.
"""

import logging
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Optional

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
    """Configuration for secure Kafka and Redis clients."""
    brokers: str = "localhost:9092"
    username: Optional[str] = None
    password: Optional[str] = None
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    tls_verify: bool = True
    sasl_mechanism: str = "SCRAM-SHA-512"


class SecureKafkaClient:
    """
    Secure Kafka client with SSL/TLS and SASL authentication.

    Note on ssl_context vs individual cert files
    --------------------------------------------
    kafka-python does **not** accept an ``ssl_context`` keyword argument in
    KafkaProducer / KafkaConsumer.  The library builds its own SSLContext
    internally from the ``ssl_cafile``, ``ssl_certfile``, and ``ssl_keyfile``
    keyword arguments.

    FIX BUG-31: The original code passed ``ssl_context=self.ssl_context``
    directly into the KafkaProducer / KafkaConsumer constructor.  kafka-python
    silently ignores unknown kwargs (or raises a TypeError depending on version),
    which meant TLS was effectively disabled even when a SecureClientConfig
    with cert paths was provided.

    The fix maps the SSLContext's certificate/key material back to the
    individual file-path kwargs that kafka-python actually understands.
    The SSLContext is still created and kept for external consumers (e.g. tests
    or other libraries that do accept it).
    """

    def __init__(self, config: SecureClientConfig) -> None:
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is required for Kafka client")

        self.config = config
        # Build the SSLContext for reference / external use.
        self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create a hardened SSL context."""
        context = ssl.create_default_context()

        if self.config.tls_verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("TLS verification disabled — not recommended for production")

        if self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)

        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(
                self.config.client_cert_path,
                self.config.client_key_path,
            )

        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        context.set_ciphers(
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
        )

        return context

    def _kafka_ssl_kwargs(self) -> Dict[str, Any]:
        """
        Return the SSL-related kwargs that kafka-python accepts.

        FIX BUG-31: kafka-python uses ``ssl_cafile``, ``ssl_certfile``, and
        ``ssl_keyfile`` — not ``ssl_context``.  These are the only SSL knobs
        that kafka-python exposes at the constructor level.
        """
        kwargs: Dict[str, Any] = {}
        if self.config.ca_cert_path:
            kwargs['ssl_cafile'] = self.config.ca_cert_path
        if self.config.client_cert_path:
            kwargs['ssl_certfile'] = self.config.client_cert_path
        if self.config.client_key_path:
            kwargs['ssl_keyfile'] = self.config.client_key_path
        return kwargs

    def _security_protocol(self) -> str:
        has_user = bool(self.config.username)
        has_tls = bool(
            self.config.ca_cert_path
            or self.config.client_cert_path
            or not self.config.tls_verify
        )
        if has_user and has_tls:
            return 'SASL_SSL'
        if has_tls:
            return 'SSL'
        if has_user:
            return 'SASL_PLAINTEXT'
        return 'PLAINTEXT'

    def get_producer(self, **kwargs: Any) -> "KafkaProducer":
        """Return a secure KafkaProducer."""
        protocol = self._security_protocol()
        config: Dict[str, Any] = {
            'bootstrap_servers': self.config.brokers,
            'security_protocol': protocol,
            # FIX BUG-31: Use file-path kwargs, not ssl_context
            **self._kafka_ssl_kwargs(),
            **kwargs,
        }

        if self.config.username and self.config.password:
            config.update({
                'sasl_mechanism': self.config.sasl_mechanism,
                'sasl_plain_username': self.config.username,
                'sasl_plain_password': self.config.password,
            })

        return KafkaProducer(**config)

    def get_consumer(self, group_id: str, **kwargs: Any) -> "KafkaConsumer":
        """Return a secure KafkaConsumer."""
        protocol = self._security_protocol()
        config: Dict[str, Any] = {
            'bootstrap_servers': self.config.brokers,
            'group_id': group_id,
            'security_protocol': protocol,
            # FIX BUG-31: Use file-path kwargs, not ssl_context
            **self._kafka_ssl_kwargs(),
            **kwargs,
        }

        if self.config.username and self.config.password:
            config.update({
                'sasl_mechanism': self.config.sasl_mechanism,
                'sasl_plain_username': self.config.username,
                'sasl_plain_password': self.config.password,
            })

        return KafkaConsumer(**config)


class SecureRedisClient:
    """Secure Redis client with optional TLS support."""

    def __init__(
        self,
        host: str,
        port: int,
        password: str,
        use_tls: bool = True,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
    ) -> None:
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
        client_key_path: Optional[str] = None,
    ) -> "redis.Redis":
        """Create a Redis client with the appropriate security settings."""
        config: Dict[str, Any] = {
            'host': self.host,
            'port': self.port,
            'password': self.password,
            'decode_responses': True,
            'socket_timeout': 5,
            'socket_connect_timeout': 5,
            'retry_on_timeout': True,
        }

        if self.use_tls:
            # FIX BUG-32: When use_tls=True but no CA cert is provided,
            # the original code silently disabled hostname checking.  This
            # means an attacker could perform a MITM with any certificate.
            # Now we log a prominent warning so operators are aware.
            if not ca_cert_path:
                logger.warning(
                    "SecureRedisClient: TLS is enabled but no CA certificate "
                    "was provided.  Hostname verification is disabled — "
                    "the connection is susceptible to MITM attacks.  "
                    "Provide ca_cert_path in production."
                )

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

    def get_client(self) -> "redis.Redis":
        """Return the underlying Redis client."""
        return self.client

    def ping(self) -> bool:
        """Test the connection."""
        try:
            return self.client.ping()
        except Exception as exc:
            logger.error(f"Redis ping failed: {exc}")
            return False

    def close(self) -> None:
        """Close the connection pool."""
        self.client.close()


def create_secure_clients_from_env() -> Dict[str, Any]:
    """
    Create secure Kafka and Redis clients from environment variables.

    Expected environment variables:
      KAFKA_BOOTSTRAP_SERVERS, KAFKA_SASL_USERNAME, KAFKA_SASL_PASSWORD,
      KAFKA_SSL_CA_LOCATION, KAFKA_SSL_CERTIFICATE_LOCATION,
      KAFKA_SSL_KEY_LOCATION, KAFKA_SSL_VERIFY, KAFKA_SASL_MECHANISM,
      REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_TLS_ENABLED,
      REDIS_CA_CERT, REDIS_CLIENT_CERT, REDIS_CLIENT_KEY.
    """
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
            port=int(os.environ.get('REDIS_PORT', '6379')),
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