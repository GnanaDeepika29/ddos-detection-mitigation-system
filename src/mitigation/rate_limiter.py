"""
Rate Limiter Module

Implements rate limiting for DDoS mitigation using various strategies:
- Token bucket algorithm
- Leaky bucket algorithm
- Sliding window counters
- Per-IP, per-subnet, per-protocol limiting
"""

import ipaddress
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


class LimitType(Enum):
    """Types of rate limits"""
    PACKET = "packet"
    BYTE = "byte"
    CONNECTION = "connection"
    BANDWIDTH = "bandwidth"


@dataclass
class RateLimitRule:
    """Rate limiting rule definition"""
    id: str
    limit_type: LimitType
    limit_value: float
    burst_value: float
    target_ip: Optional[str] = None
    target_subnet: Optional[str] = None
    protocol: Optional[int] = None
    port: Optional[int] = None
    duration_seconds: int = 300
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if rule has expired"""
        return bool(self.expires_at and time.time() > self.expires_at)

    def matches(self, ip: str, protocol: Optional[int] = None, port: Optional[int] = None) -> bool:
        """Check if rule matches given traffic"""
        if self.target_ip and ip != self.target_ip:
            return False

        if self.target_subnet:
            try:
                if ipaddress.ip_address(ip) not in ipaddress.ip_network(self.target_subnet, strict=False):
                    return False
            except ValueError:
                return False

        if self.protocol is not None and protocol != self.protocol:
            return False

        if self.port is not None and port != self.port:
            return False

        return True


class TokenBucket:
    """Token bucket algorithm for rate limiting"""

    def __init__(self, rate: float, burst: float):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """Consume tokens from bucket"""
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now

    def get_tokens(self) -> float:
        """Get current token count"""
        with self.lock:
            self._refill()
            return self.tokens


class SlidingWindowCounter:
    """Sliding window counter for accurate rate limiting"""

    def __init__(self, window_seconds: int = 1, max_requests: int = 1000):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.requests: deque = deque()
        self.lock = threading.Lock()

    def allow_request(self) -> bool:
        """Check if request should be allowed"""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            # Remove old requests
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def get_count(self) -> int:
        """Get current request count in window"""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            return len(self.requests)


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiter"""
    default_packet_rate: int = 1000
    default_byte_rate: int = 1_048_576  # 1 MB/s
    default_connection_rate: int = 100
    default_burst_multiplier: float = 2.0
    enable_auto_rules: bool = True
    max_rules: int = 10_000
    rule_cleanup_interval: int = 60
    use_sliding_window: bool = True


class RateLimiter:
    """
    Distributed rate limiter for DDoS mitigation.
    Supports multiple limiting strategies and automatic rule management.
    """

    def __init__(self, config: Optional[RateLimiterConfig] = None):
        self.config = config or RateLimiterConfig()
        self.rules: Dict[str, RateLimitRule] = {}
        self.buckets: Dict[str, TokenBucket] = {}
        self.windows: Dict[str, SlidingWindowCounter] = {}
        self.stats: Dict[str, Any] = {
            'packets_allowed': 0,
            'packets_limited': 0,
            'active_limits': 0,
            'rules_created': 0,
            'rules_expired': 0,
        }

        self._lock = threading.RLock()
        self._rule_counter = 0
        self._last_cleanup = time.time()
        self._running = True
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        logger.info(f"RateLimiter initialized with default rate: {self.config.default_packet_rate} pps")

    def _generate_rule_id(self) -> str:
        """Generate unique rule ID"""
        self._rule_counter += 1
        return f"rate_limit_{int(time.time())}_{self._rule_counter}"

    def _get_bucket_key(self, rule_id: str, ip: str, protocol: Optional[int]) -> str:
        """Generate bucket key for rate limiting state"""
        return f"{rule_id}:{ip}:{protocol or 'any'}"

    def _rate_state_key(self, rule: RateLimitRule, ip: str, protocol: Optional[int]) -> str:
        """Generate rate state key"""
        if rule.target_subnet:
            return f"{rule.id}:subnet:{rule.target_subnet}:{protocol or 'any'}"
        return self._get_bucket_key(rule.id, ip, protocol)

    def _get_bucket(self, key: str, rate: float, burst: float) -> TokenBucket:
        """Get or create token bucket"""
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(rate, burst)
        return self.buckets[key]

    def _get_window(self, key: str, max_requests: int) -> SlidingWindowCounter:
        """Get or create sliding window counter"""
        if key not in self.windows:
            self.windows[key] = SlidingWindowCounter(1, max_requests)
        return self.windows[key]

    def add_rule(self, rule: RateLimitRule) -> str:
        """Add a rate limiting rule"""
        with self._lock:
            # Clean up if needed
            if len(self.rules) >= self.config.max_rules:
                self._cleanup_expired_rules()

            # Generate ID and set expiration
            rule.id = self._generate_rule_id()
            if rule.expires_at is None:
                rule.expires_at = time.time() + rule.duration_seconds

            self.rules[rule.id] = rule
            self.stats['rules_created'] += 1
            self.stats['active_limits'] = len(self.rules)

            logger.info(
                f"Added rate limit rule: {rule.limit_type.value}={rule.limit_value}/s "
                f"for {rule.target_ip or rule.target_subnet or 'all'}"
            )
            return rule.id

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rate limiting rule"""
        with self._lock:
            if rule_id not in self.rules:
                return False

            del self.rules[rule_id]

            # Clean up associated state
            prefix = f"{rule_id}:"
            for key in [k for k in self.buckets if k.startswith(prefix)]:
                del self.buckets[key]
            for key in [k for k in self.windows if k.startswith(prefix)]:
                del self.windows[key]

            self.stats['active_limits'] = len(self.rules)
            logger.info(f"Removed rate limit rule: {rule_id}")
            return True

    def _cleanup_expired_rules(self):
        """Remove expired rules"""
        expired = [rid for rid, rule in self.rules.items() if rule.is_expired()]
        for rule_id in expired:
            self.remove_rule(rule_id)
            self.stats['rules_expired'] += 1

        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired rate limit rules")

    def _cleanup_loop(self):
        """Background cleanup thread"""
        while self._running:
            time.sleep(self.config.rule_cleanup_interval)
            with self._lock:
                self._cleanup_expired_rules()

    def check_rate_limit(
        self,
        ip: str,
        packets: int = 1,
        bytes_count: int = 0,
        protocol: Optional[int] = None,
        port: Optional[int] = None,
    ) -> bool:
        """
        Check if traffic should be rate limited.
        Returns True if traffic is allowed, False if it should be dropped.
        """
        allowed = True

        for rule in self.rules.values():
            if not rule.matches(ip, protocol, port):
                continue

            if rule.limit_type == LimitType.PACKET:
                key = self._rate_state_key(rule, ip, protocol)
                if self.config.use_sliding_window:
                    if not self._get_window(key, int(rule.limit_value)).allow_request():
                        allowed = False
                else:
                    if not self._get_bucket(key, rule.limit_value, rule.burst_value).consume(packets):
                        allowed = False

            elif rule.limit_type == LimitType.BYTE:
                key = self._rate_state_key(rule, ip, protocol)
                if not self._get_bucket(key, rule.limit_value, rule.burst_value).consume(bytes_count):
                    allowed = False

            elif rule.limit_type == LimitType.CONNECTION:
                key = self._rate_state_key(rule, ip, protocol)
                if self.config.use_sliding_window:
                    if not self._get_window(key, int(rule.limit_value)).allow_request():
                        allowed = False
                else:
                    if not self._get_bucket(key, rule.limit_value, rule.burst_value).consume(1):
                        allowed = False

        if allowed:
            self.stats['packets_allowed'] += packets
        else:
            self.stats['packets_limited'] += packets

        return allowed

    def rate_limit_ip(self, ip: str, rate_pps: Optional[int] = None, duration_seconds: int = 300) -> Optional[str]:
        """Apply rate limiting to a specific IP"""
        rate = rate_pps or self.config.default_packet_rate
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=float(rate),
            burst_value=float(rate),
            target_ip=ip,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_subnet(self, subnet: str, rate_pps: Optional[int] = None, duration_seconds: int = 300) -> Optional[str]:
        """Apply rate limiting to a subnet"""
        rate = rate_pps or self.config.default_packet_rate
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=float(rate),
            burst_value=float(rate),
            target_subnet=subnet,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_protocol(self, protocol: int, rate_pps: int, duration_seconds: int = 300) -> Optional[str]:
        """Apply rate limiting to a protocol"""
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=float(rate_pps),
            burst_value=float(rate_pps),
            protocol=protocol,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_bandwidth(self, ip: str, bps: int, duration_seconds: int = 300) -> Optional[str]:
        """Apply bandwidth limiting to an IP"""
        bytes_per_sec = bps // 8
        byte_mult = max(2.0, self.config.default_burst_multiplier)
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.BYTE,
            limit_value=float(bytes_per_sec),
            burst_value=float(bytes_per_sec * byte_mult),
            target_ip=ip,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get list of active rules"""
        return [
            {
                'id': rule.id,
                'type': rule.limit_type.value,
                'limit': rule.limit_value,
                'burst': rule.burst_value,
                'target_ip': rule.target_ip,
                'target_subnet': rule.target_subnet,
                'protocol': rule.protocol,
                'expires_at': rule.expires_at,
                'created_at': rule.created_at,
            }
            for rule in self.rules.values()
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            **self.stats,
            'active_rules': len(self.rules),
            'active_buckets': len(self.buckets),
            'active_windows': len(self.windows),
            'default_packet_rate': self.config.default_packet_rate,
            'use_sliding_window': self.config.use_sliding_window,
        }

    def stop(self):
        """Stop the rate limiter"""
        self._running = False
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        logger.info("RateLimiter stopped")

    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'packets_allowed': 0,
            'packets_limited': 0,
            'active_limits': len(self.rules),
            'rules_created': self.stats['rules_created'],
            'rules_expired': self.stats['rules_expired'],
        }


class DistributedRateLimiter(RateLimiter):
    """Distributed rate limiter using Redis for cross-instance coordination"""

    def __init__(
        self,
        config: RateLimiterConfig,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
    ):
        super().__init__(config)
        self.redis_client = None
        self._init_redis(redis_host, redis_port, redis_password)
        logger.info("DistributedRateLimiter initialized with Redis backend")

    def _init_redis(self, host: str, port: int, password: Optional[str]):
        """Initialize Redis client"""
        try:
            import redis
            self.redis_client = redis.Redis(
                host=host, 
                port=port, 
                password=password,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            self.redis_client.ping()
            logger.info("Redis connection established")
        except ImportError:
            logger.error("Redis package not installed, falling back to local rate limiting")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")

    def check_rate_limit_distributed(
        self, ip: str, limit_key: str, limit_value: int, window_seconds: int = 1
    ) -> bool:
        """Check rate limit using Redis for distributed coordination"""
        if not self.redis_client:
            return super().check_rate_limit(ip, 1, 0, None, None)

        try:
            key = f"rate_limit:{limit_key}:{ip}"
            current = self.redis_client.incr(key)

            if current == 1:
                self.redis_client.expire(key, window_seconds)

            if current > limit_value:
                self.stats['packets_limited'] += 1
                return False

            self.stats['packets_allowed'] += 1
            return True

        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            return True  # fail open
