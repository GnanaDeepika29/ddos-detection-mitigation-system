"""
Health Check and Readiness Probes for DDoS Detection System
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaConsumer, KafkaAdminClient
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from influxdb_client import InfluxDBClient
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


@dataclass
class DependencyConfig:
    name: str
    check_func: Callable[[], Awaitable[bool]]
    timeout_seconds: int = 30
    retry_interval_seconds: int = 2
    required: bool = True


@dataclass
class HealthStatus:
    name: str
    healthy: bool
    message: str
    last_check: float
    response_time_ms: float
    details: Dict[str, Any] = field(default_factory=dict)


class DependencyHealthChecker:
    """Health checker for system dependencies."""

    def __init__(self) -> None:
        self.dependencies: Dict[str, DependencyConfig] = {}
        self.status_cache: Dict[str, HealthStatus] = {}
        self._check_interval = 10
        logger.info("DependencyHealthChecker initialised")

    def register_dependency(
        self,
        name: str,
        check_func: Callable[[], Awaitable[bool]],
        timeout: int = 30,
        required: bool = True,
    ) -> None:
        self.dependencies[name] = DependencyConfig(
            name=name, check_func=check_func,
            timeout_seconds=timeout, required=required,
        )
        logger.info(f"Registered dependency: {name} (required={required})")

    async def check_kafka_ready(
        self, bootstrap_servers: str, topic: str, timeout: int = 30
    ) -> bool:
        if not KAFKA_AVAILABLE:
            logger.error("Kafka library not available")
            return False
        consumer = None
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap_servers,
                consumer_timeout_ms=1_000,
                max_poll_records=1,
                request_timeout_ms=timeout * 1_000,
                api_version_auto_timeout_ms=5_000,
            )
            partitions = consumer.partitions_for_topic(topic)
            healthy = bool(partitions)
            if healthy:
                logger.debug(f"Kafka ready: topic '{topic}' has {len(partitions)} partitions")
            else:
                logger.warning(f"Kafka topic '{topic}' has no partitions")
            return healthy
        except Exception as exc:
            logger.warning(f"Kafka not ready: {exc}")
            return False
        finally:
            if consumer:
                consumer.close()

    async def check_redis_ready(
        self,
        host: str,
        port: int,
        password: Optional[str] = None,
        timeout: int = 5,
    ) -> bool:
        if not REDIS_AVAILABLE:
            logger.error("Redis library not available")
            return False
        client = None
        try:
            client = redis.Redis(
                host=host, port=port, password=password,
                socket_timeout=timeout, socket_connect_timeout=timeout,
                decode_responses=True,
            )
            healthy = await client.ping() is True
            if healthy:
                logger.debug(f"Redis ready at {host}:{port}")
            return healthy
        except Exception as exc:
            logger.warning(f"Redis not ready: {exc}")
            return False
        finally:
            if client:
                await client.close()

    async def check_influxdb_ready(
        self, url: str, token: str, org: str, bucket: str, timeout: int = 10
    ) -> bool:
        if not INFLUXDB_AVAILABLE:
            logger.error("InfluxDB client not available")
            return False
        client = None
        try:
            client = InfluxDBClient(url=url, token=token, org=org, timeout=timeout * 1_000)
            found = client.buckets_api().find_bucket_by_name(bucket)
            healthy = found is not None
            if healthy:
                logger.debug(f"InfluxDB ready: bucket '{bucket}' exists")
            else:
                logger.warning(f"InfluxDB bucket '{bucket}' not found")
            return healthy
        except Exception as exc:
            logger.warning(f"InfluxDB not ready: {exc}")
            return False
        finally:
            if client:
                client.close()

    async def check_postgres_ready(
        self,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        timeout: int = 10,
    ) -> bool:
        if not POSTGRES_AVAILABLE:
            logger.error("PostgreSQL library not available")
            return False
        try:
            # FIX BUG-22: asyncio.get_running_loop() replaces deprecated
            # asyncio.get_event_loop() — always valid inside a coroutine.
            loop = asyncio.get_running_loop()

            def _sync_check() -> bool:
                conn = psycopg2.connect(
                    host=host, port=port, database=database,
                    user=user, password=password, connect_timeout=timeout,
                )
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                cursor.close()
                conn.close()
                return result is not None

            result = await loop.run_in_executor(None, _sync_check)
            if result:
                logger.debug(f"PostgreSQL ready at {host}:{port}/{database}")
            return result
        except Exception as exc:
            logger.warning(f"PostgreSQL not ready: {exc}")
            return False

    async def check_elasticsearch_ready(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10,
    ) -> bool:
        if not ELASTICSEARCH_AVAILABLE:
            logger.error("Elasticsearch library not available")
            return False
        try:
            params: Dict[str, Any] = {
                'hosts': hosts,
                'timeout': timeout,
                'request_timeout': timeout,
            }
            if username and password:
                params['basic_auth'] = (username, password)
            es = Elasticsearch(**params)
            health = es.cluster.health()
            status = health.get('status', 'unknown')
            healthy = status in ('green', 'yellow')
            if healthy:
                logger.debug(f"Elasticsearch ready: cluster status={status}")
            else:
                logger.warning(f"Elasticsearch not ready: cluster status={status}")
            return healthy
        except Exception as exc:
            logger.warning(f"Elasticsearch not ready: {exc}")
            return False

    async def check_alertmanager_ready(self, url: str, timeout: int = 10) -> bool:
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available")
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{url}/api/v2/status", timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    healthy = response.status == 200
                    if healthy:
                        logger.debug(f"Alertmanager ready at {url}")
                    else:
                        logger.warning(f"Alertmanager returned {response.status}")
                    return healthy
        except Exception as exc:
            logger.warning(f"Alertmanager not ready: {exc}")
            return False

    async def check_dependency(self, dep_config: DependencyConfig) -> HealthStatus:
        start = time.time()
        try:
            result = await asyncio.wait_for(
                dep_config.check_func(), timeout=dep_config.timeout_seconds
            )
            rt_ms = (time.time() - start) * 1_000
            return HealthStatus(
                name=dep_config.name,
                healthy=result,
                message="OK" if result else "Check failed",
                last_check=time.time(),
                response_time_ms=rt_ms,
                details={'required': dep_config.required},
            )
        except asyncio.TimeoutError:
            rt_ms = (time.time() - start) * 1_000
            return HealthStatus(
                name=dep_config.name, healthy=False,
                message=f"Timeout after {dep_config.timeout_seconds}s",
                last_check=time.time(), response_time_ms=rt_ms,
                details={'required': dep_config.required},
            )
        except Exception as exc:
            rt_ms = (time.time() - start) * 1_000
            return HealthStatus(
                name=dep_config.name, healthy=False, message=str(exc),
                last_check=time.time(), response_time_ms=rt_ms,
                details={'required': dep_config.required},
            )

    async def check_all(self, use_cache: bool = True) -> List[HealthStatus]:
        results = []
        for name, dep_config in self.dependencies.items():
            if use_cache and name in self.status_cache:
                cached = self.status_cache[name]
                if time.time() - cached.last_check < self._check_interval:
                    results.append(cached)
                    continue
            status = await self.check_dependency(dep_config)
            self.status_cache[name] = status
            results.append(status)
            if not status.healthy:
                logger.warning(f"Dependency {name} unhealthy: {status.message}")
        return results

    async def wait_for_dependencies(
        self,
        dependencies: Dict[str, Callable[[], Awaitable[bool]]],
        timeout: int = 60,
    ) -> bool:
        """Wait until all required dependencies are ready or timeout elapses."""
        for name, check_func in dependencies.items():
            self.register_dependency(name, check_func)

        # FIX BUG-21: asyncio.get_running_loop() replaces deprecated
        # asyncio.get_event_loop() — always valid inside a coroutine.
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        last_logged = start_time

        while (loop.time() - start_time) < timeout:
            all_ready = True
            results = await self.check_all(use_cache=False)

            for status in results:
                if not status.healthy and self.dependencies[status.name].required:
                    all_ready = False
                    break

            if all_ready:
                logger.info("✅ All dependencies ready")
                return True

            current = loop.time()
            if current - last_logged >= 10:
                unhealthy = [s.name for s in results if not s.healthy]
                logger.info(f"Waiting for dependencies: {', '.join(unhealthy)}")
                last_logged = current

            await asyncio.sleep(2)

        final = await self.check_all(use_cache=False)
        unhealthy = [
            s.name for s in final
            if not s.healthy and self.dependencies[s.name].required
        ]
        logger.error(
            f"Timeout after {timeout}s — dependencies not ready: {', '.join(unhealthy)}"
        )
        return False

    def get_health_summary(self) -> Dict[str, Any]:
        return {
            'timestamp': datetime.now().isoformat(),
            'total_dependencies': len(self.dependencies),
            'healthy_count': sum(1 for s in self.status_cache.values() if s.healthy),
            'unhealthy_count': sum(1 for s in self.status_cache.values() if not s.healthy),
            'dependencies': {
                name: {
                    'healthy': status.healthy,
                    'message': status.message,
                    'response_time_ms': status.response_time_ms,
                    'last_check': status.last_check,
                }
                for name, status in self.status_cache.items()
            },
        }

    def is_ready(self) -> bool:
        for name, status in self.status_cache.items():
            dep = self.dependencies.get(name)
            if dep and dep.required and not status.healthy:
                return False
        return True


def create_health_checker() -> DependencyHealthChecker:
    return DependencyHealthChecker()


async def kubernetes_readiness_check() -> bool:
    """Kubernetes readiness probe."""
    checker = DependencyHealthChecker()

    kafka_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', '')
    kafka_topic = os.environ.get('KAFKA_TOPIC_FLOWS', 'network_flows')
    if kafka_servers:
        checker.register_dependency(
            'kafka',
            lambda: checker.check_kafka_ready(kafka_servers, kafka_topic),
            required=True,
        )

    redis_host = os.environ.get('REDIS_HOST', '')
    if redis_host:
        redis_port = int(os.environ.get('REDIS_PORT', '6379'))
        redis_password = os.environ.get('REDIS_PASSWORD') or None
        checker.register_dependency(
            'redis',
            lambda: checker.check_redis_ready(redis_host, redis_port, redis_password),
            required=True,
        )

    influxdb_url = os.environ.get('INFLUXDB_URL', '')
    if influxdb_url:
        checker.register_dependency(
            'influxdb',
            lambda: checker.check_influxdb_ready(
                influxdb_url,
                os.environ.get('INFLUXDB_TOKEN', ''),
                os.environ.get('INFLUXDB_ORG', ''),
                os.environ.get('INFLUXDB_BUCKET', 'metrics'),
            ),
            required=False,
        )

    results = await checker.check_all()
    return all(
        status.healthy or not checker.dependencies[status.name].required
        for status in results
    )


def sync_readiness_check() -> bool:
    """
    Synchronous wrapper for use in startup scripts.

    FIX BUG-25: Replaced the fragile get_event_loop() / new_event_loop()
    pattern with asyncio.run(), which is the canonical way to run a
    top-level coroutine and works correctly in Python ≥3.10.
    """
    return asyncio.run(kubernetes_readiness_check())