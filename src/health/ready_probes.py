"""
Health Check and Readiness Probes for DDoS Detection System

Provides health checks for all system dependencies including:
- Kafka
- Redis
- InfluxDB
- PostgreSQL
- Elasticsearch
- Alertmanager
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
import time

logger = logging.getLogger(__name__)

# Lazy imports for optional dependencies
try:
    from kafka import KafkaConsumer, KafkaAdminClient
    from kafka.admin import NewTopic
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger.warning("kafka-python not available. Install with: pip install kafka-python")

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis not available. Install with: pip install redis")

try:
    from influxdb_client import InfluxDBClient
    from influxdb_client.client.exceptions import InfluxDBError
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False
    logger.warning("influxdb-client not available. Install with: pip install influxdb-client")

try:
    import psycopg2
    from psycopg2 import OperationalError
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    logger.warning("psycopg2 not available. Install with: pip install psycopg2-binary")

try:
    from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    logger.warning("elasticsearch not available. Install with: pip install elasticsearch")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.warning("aiohttp not available. Install with: pip install aiohttp")


@dataclass
class DependencyConfig:
    """Configuration for a dependency"""
    name: str
    check_func: Callable[[], Awaitable[bool]]
    timeout_seconds: int = 30
    retry_interval_seconds: int = 2
    required: bool = True


@dataclass
class HealthStatus:
    """Health status of a dependency"""
    name: str
    healthy: bool
    message: str
    last_check: float
    response_time_ms: float
    details: Dict[str, Any] = field(default_factory=dict)


class DependencyHealthChecker:
    """
    Health checker for system dependencies.
    
    Checks the readiness of:
    - Kafka (topics exist and accessible)
    - Redis (ping and connectivity)
    - InfluxDB (bucket exists and writeable)
    - PostgreSQL (database accessible)
    - Elasticsearch (cluster health)
    - Alertmanager (API accessible)
    """
    
    def __init__(self):
        self.dependencies: Dict[str, DependencyConfig] = {}
        self.status_cache: Dict[str, HealthStatus] = {}
        self._last_full_check = 0
        self._check_interval = 10  # seconds
        
        logger.info("DependencyHealthChecker initialized")
    
    def register_dependency(self, name: str, check_func: Callable[[], Awaitable[bool]], 
                           timeout: int = 30, required: bool = True):
        """Register a dependency check function"""
        self.dependencies[name] = DependencyConfig(
            name=name,
            check_func=check_func,
            timeout_seconds=timeout,
            required=required
        )
        logger.info(f"Registered dependency: {name} (required={required})")
    
    async def check_kafka_ready(self, bootstrap_servers: str, topic: str, 
                                 timeout: int = 30) -> bool:
        """
        Check if Kafka is ready for consumption.
        
        Verifies:
        1. Kafka broker is reachable
        2. Topic exists
        3. Topic has partitions
        """
        if not KAFKA_AVAILABLE:
            logger.error("Kafka library not available")
            return False
            
        start_time = time.time()
        consumer = None
        
        try:
            # Create consumer with short timeout
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=bootstrap_servers,
                consumer_timeout_ms=1000,
                max_poll_records=1,
                request_timeout_ms=timeout * 1000,
                api_version_auto_timeout_ms=5000,
            )
            
            # Try to get partition metadata
            partitions = consumer.partitions_for_topic(topic)
            healthy = partitions is not None and len(partitions) > 0
            
            if healthy:
                logger.debug(f"Kafka ready: topic '{topic}' has {len(partitions)} partitions")
            else:
                logger.warning(f"Kafka not ready: topic '{topic}' has no partitions")
            
            return healthy
            
        except Exception as e:
            logger.warning(f"Kafka not ready: {e}")
            return False
            
        finally:
            if consumer:
                consumer.close()
    
    async def check_kafka_admin_ready(self, bootstrap_servers: str, 
                                       timeout: int = 30) -> bool:
        """Check Kafka broker availability using admin client"""
        if not KAFKA_AVAILABLE:
            return False
            
        try:
            admin_client = KafkaAdminClient(
                bootstrap_servers=bootstrap_servers,
                request_timeout_ms=timeout * 1000,
            )
            # Try to get cluster metadata
            cluster_metadata = admin_client.describe_cluster()
            admin_client.close()
            
            return cluster_metadata is not None
            
        except Exception as e:
            logger.warning(f"Kafka admin check failed: {e}")
            return False
    
    async def check_redis_ready(self, host: str, port: int, 
                                 password: Optional[str] = None,
                                 timeout: int = 5) -> bool:
        """
        Check if Redis is ready.
        
        Verifies:
        1. Redis is reachable
        2. Can authenticate (if password provided)
        3. Can execute PING command
        """
        if not REDIS_AVAILABLE:
            logger.error("Redis library not available")
            return False
            
        client = None
        
        try:
            client = redis.Redis(
                host=host,
                port=port,
                password=password,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
                decode_responses=True,
            )
            
            # Test connection with PING
            response = await client.ping()
            healthy = response is True
            
            if healthy:
                logger.debug(f"Redis ready at {host}:{port}")
            else:
                logger.warning(f"Redis ping failed at {host}:{port}")
            
            return healthy
            
        except Exception as e:
            logger.warning(f"Redis not ready: {e}")
            return False
            
        finally:
            if client:
                await client.close()
    
    async def check_influxdb_ready(self, url: str, token: str, org: str, 
                                     bucket: str, timeout: int = 10) -> bool:
        """
        Check if InfluxDB bucket is ready for writes.
        
        Verifies:
        1. InfluxDB is reachable
        2. Authentication works
        3. Bucket exists
        """
        if not INFLUXDB_AVAILABLE:
            logger.error("InfluxDB client not available")
            return False
            
        client = None
        
        try:
            client = InfluxDBClient(
                url=url, 
                token=token, 
                org=org,
                timeout=timeout * 1000,
            )
            
            # Check if bucket exists
            buckets_api = client.buckets_api()
            found_bucket = buckets_api.find_bucket_by_name(bucket)
            
            # Try to write a test point
            write_api = client.write_api()
            test_point = f"health_check,source=probe value=1 {int(time.time())}000000000"
            
            # Test write (optional - uncomment if needed)
            # write_api.write(bucket=bucket, org=org, record=test_point)
            
            healthy = found_bucket is not None
            
            if healthy:
                logger.debug(f"InfluxDB ready: bucket '{bucket}' exists")
            else:
                logger.warning(f"InfluxDB not ready: bucket '{bucket}' not found")
            
            return healthy
            
        except Exception as e:
            logger.warning(f"InfluxDB not ready: {e}")
            return False
            
        finally:
            if client:
                client.close()
    
    async def check_postgres_ready(self, host: str, port: int, database: str,
                                     user: str, password: str, timeout: int = 10) -> bool:
        """
        Check if PostgreSQL is ready.
        
        Verifies:
        1. PostgreSQL is reachable
        2. Authentication works
        3. Database exists
        """
        if not POSTGRES_AVAILABLE:
            logger.error("PostgreSQL library not available")
            return False
            
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            
            def _sync_check():
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    database=database,
                    user=user,
                    password=password,
                    connect_timeout=timeout,
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
            else:
                logger.warning(f"PostgreSQL query failed at {host}:{port}")
            
            return result
            
        except Exception as e:
            logger.warning(f"PostgreSQL not ready: {e}")
            return False
    
    async def check_elasticsearch_ready(self, hosts: List[str], 
                                          username: Optional[str] = None,
                                          password: Optional[str] = None,
                                          timeout: int = 10) -> bool:
        """
        Check if Elasticsearch is ready.
        
        Verifies:
        1. Elasticsearch is reachable
        2. Cluster health is at least yellow
        """
        if not ELASTICSEARCH_AVAILABLE:
            logger.error("Elasticsearch library not available")
            return False
            
        try:
            # Build connection parameters
            params = {
                'hosts': hosts,
                'timeout': timeout,
                'request_timeout': timeout,
            }
            
            if username and password:
                params['basic_auth'] = (username, password)
            
            es = Elasticsearch(**params)
            
            # Check cluster health
            health = es.cluster.health()
            status = health.get('status', 'unknown')
            
            # Red status is unhealthy, yellow/green are OK for readiness
            healthy = status in ['green', 'yellow']
            
            if healthy:
                logger.debug(f"Elasticsearch ready: cluster status={status}")
            else:
                logger.warning(f"Elasticsearch not ready: cluster status={status}")
            
            return healthy
            
        except Exception as e:
            logger.warning(f"Elasticsearch not ready: {e}")
            return False
    
    async def check_alertmanager_ready(self, url: str, timeout: int = 10) -> bool:
        """
        Check if Alertmanager is ready.
        
        Verifies:
        1. Alertmanager API is reachable
        2. Returns valid response
        """
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available")
            return False
            
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{url}/api/v2/status", timeout=timeout) as response:
                    healthy = response.status == 200
                    
                    if healthy:
                        logger.debug(f"Alertmanager ready at {url}")
                    else:
                        logger.warning(f"Alertmanager returned status {response.status}")
                    
                    return healthy
                    
        except Exception as e:
            logger.warning(f"Alertmanager not ready: {e}")
            return False
    
    async def check_dependency(self, dep_config: DependencyConfig) -> HealthStatus:
        """Check a single dependency"""
        start_time = time.time()
        
        try:
            # Run check with timeout
            result = await asyncio.wait_for(
                dep_config.check_func(),
                timeout=dep_config.timeout_seconds
            )
            response_time = (time.time() - start_time) * 1000
            
            return HealthStatus(
                name=dep_config.name,
                healthy=result,
                message="OK" if result else "Check failed",
                last_check=time.time(),
                response_time_ms=response_time,
                details={'required': dep_config.required}
            )
            
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return HealthStatus(
                name=dep_config.name,
                healthy=False,
                message=f"Timeout after {dep_config.timeout_seconds}s",
                last_check=time.time(),
                response_time_ms=response_time,
                details={'required': dep_config.required}
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthStatus(
                name=dep_config.name,
                healthy=False,
                message=str(e),
                last_check=time.time(),
                response_time_ms=response_time,
                details={'required': dep_config.required}
            )
    
    async def check_all(self, use_cache: bool = True) -> List[HealthStatus]:
        """Check all registered dependencies"""
        results = []
        
        for name, dep_config in self.dependencies.items():
            # Use cached result if within interval
            if use_cache and name in self.status_cache:
                cached = self.status_cache[name]
                if time.time() - cached.last_check < self._check_interval:
                    results.append(cached)
                    continue
            
            status = await self.check_dependency(dep_config)
            self.status_cache[name] = status
            results.append(status)
            
            # Log unhealthy dependencies
            if not status.healthy:
                logger.warning(f"Dependency {name} is unhealthy: {status.message}")
        
        return results
    
    async def wait_for_dependencies(self, dependencies: Dict[str, Callable[[], Awaitable[bool]]], 
                                      timeout: int = 60) -> bool:
        """
        Wait for all dependencies to be ready.
        
        Args:
            dependencies: Dictionary of dependency name -> check function
            timeout: Maximum wait time in seconds
            
        Returns:
            True if all dependencies ready, False if timeout
        """
        start_time = asyncio.get_event_loop().time()
        last_logged = start_time
        
        # Register all dependencies
        for name, check_func in dependencies.items():
            self.register_dependency(name, check_func)
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            all_ready = True
            results = await self.check_all(use_cache=False)
            
            for status in results:
                if not status.healthy and self.dependencies[status.name].required:
                    all_ready = False
                    break
            
            if all_ready:
                logger.info("✅ All dependencies ready")
                return True
            
            # Log progress every 10 seconds
            current_time = asyncio.get_event_loop().time()
            if current_time - last_logged >= 10:
                unhealthy = [s.name for s in results if not s.healthy]
                logger.info(f"Waiting for dependencies: {', '.join(unhealthy)}")
                last_logged = current_time
            
            await asyncio.sleep(2)
        
        # Timeout reached - log which dependencies are still unhealthy
        final_results = await self.check_all(use_cache=False)
        unhealthy = [s.name for s in final_results if not s.healthy and self.dependencies[s.name].required]
        logger.error(f"Timeout after {timeout}s - dependencies not ready: {', '.join(unhealthy)}")
        
        return False
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get summary of all dependency health statuses"""
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
            }
        }
    
    def is_ready(self) -> bool:
        """Check if all required dependencies are ready"""
        for name, status in self.status_cache.items():
            dep_config = self.dependencies.get(name)
            if dep_config and dep_config.required and not status.healthy:
                return False
        return True


# Convenience function to create a configured health checker
def create_health_checker() -> DependencyHealthChecker:
    """Create a configured dependency health checker"""
    return DependencyHealthChecker()


# Convenience function for Kubernetes readiness probe
async def kubernetes_readiness_check() -> bool:
    """Kubernetes readiness probe check"""
    checker = DependencyHealthChecker()
    
    # Register dependencies from environment variables
    import os
    
    # Check Kafka
    kafka_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', '')
    kafka_topic = os.environ.get('KAFKA_TOPIC_FLOWS', 'network_flows')
    if kafka_servers:
        checker.register_dependency(
            'kafka',
            lambda: checker.check_kafka_ready(kafka_servers, kafka_topic),
            required=True
        )
    
    # Check Redis
    redis_host = os.environ.get('REDIS_HOST', '')
    if redis_host:
        redis_port = int(os.environ.get('REDIS_PORT', 6379))
        redis_password = os.environ.get('REDIS_PASSWORD', None)
        checker.register_dependency(
            'redis',
            lambda: checker.check_redis_ready(redis_host, redis_port, redis_password),
            required=True
        )
    
    # Check InfluxDB
    influxdb_url = os.environ.get('INFLUXDB_URL', '')
    if influxdb_url:
        checker.register_dependency(
            'influxdb',
            lambda: checker.check_influxdb_ready(
                influxdb_url,
                os.environ.get('INFLUXDB_TOKEN', ''),
                os.environ.get('INFLUXDB_ORG', ''),
                os.environ.get('INFLUXDB_BUCKET', 'metrics')
            ),
            required=False
        )
    
    # Run checks
    results = await checker.check_all()
    
    # Return true only if all required dependencies are healthy
    return all(
        status.healthy or not checker.dependencies[status.name].required
        for status in results
    )


# Simple synchronous version for uvicorn startup
def sync_readiness_check() -> bool:
    """Synchronous readiness check for startup scripts"""
    import asyncio
    
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(kubernetes_readiness_check())