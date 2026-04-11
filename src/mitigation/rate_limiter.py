"""
Distributed rate limiting for DDoS mitigation.
"""

import ipaddress
import random
import time
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


class LimitType(Enum):
    PACKET = "packet"
    BYTE = "byte"
    CONNECTION = "connection"
    BANDWIDTH = "bandwidth"


class RateLimiterAlgorithm(Enum):
    TOKEN_BUCKET = "token_bucket"
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW_LOG = "sliding_window_log"


@dataclass
class RateLimitRule:
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
        return bool(self.expires_at and time.time() > self.expires_at)

    def matches(
        self,
        ip: str,
        protocol: Optional[int] = None,
        port: Optional[int] = None,
    ) -> bool:
        if self.target_ip and ip != self.target_ip:
            return False
        if self.target_subnet:
            try:
                if ipaddress.ip_address(ip) not in ipaddress.ip_network(
                    self.target_subnet, strict=False
                ):
                    return False
            except ValueError:
                return False
        if self.protocol is not None and protocol != self.protocol:
            return False
        if self.port is not None and port != self.port:
            return False
        return True


class TokenBucket:
    """Token bucket for rate limiting."""

    def __init__(self, rate: float, burst: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        now = time.time()
        self.tokens = min(self.burst, self.tokens + (now - self.last_update) * self.rate)
        self.last_update = now

    def get_tokens(self) -> float:
        with self.lock:
            self._refill()
            return self.tokens


class SlidingWindowCounter:
    """Accurate sliding-window counter for rate limiting."""

    def __init__(self, window_seconds: int = 1, max_requests: int = 1000) -> None:
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.requests: deque = deque()
        self.lock = threading.Lock()

    def allow_request(self) -> bool:
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def get_count(self) -> int:
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            return len(self.requests)


@dataclass
class RateLimiterConfig:
    default_packet_rate: int = 1_000
    default_byte_rate: int = 1_048_576   # 1 MB/s
    default_connection_rate: int = 100
    default_burst_multiplier: float = 2.0
    enable_auto_rules: bool = True
    max_rules: int = 5_000
    rule_cleanup_interval: int = 60
    use_sliding_window: bool = True


class RateLimiter:
    """
    Distributed rate limiter for DDoS mitigation.
    Supports multiple limiting strategies and automatic rule management.
    """

    def __init__(self, config: Optional[RateLimiterConfig] = None) -> None:
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
        self._stop_event = threading.Event()
        self._max_buckets = 2000
        self._max_windows = 2000

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="rate-limiter-cleanup"
        )
        self._cleanup_thread.start()

        logger.info(
            f"RateLimiter initialised with default rate: "
            f"{self.config.default_packet_rate} pps"
        )

    def _generate_rule_id(self) -> str:
        """Generate unique rule ID.  Must be called while self._lock is held."""
        self._rule_counter += 1  # FIX BUG-7: always runs under _lock from add_rule()
        return f"rate_limit_{int(time.time())}_{self._rule_counter}"

    def _rate_state_key(
        self, rule: RateLimitRule, ip: str, protocol: Optional[int]
    ) -> str:
        if rule.target_subnet:
            return f"{rule.id}:subnet:{rule.target_subnet}:{protocol or 'any'}"
        return f"{rule.id}:{ip}:{protocol or 'any'}"

    def _get_bucket(self, key: str, rate: float, burst: float) -> TokenBucket:
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(rate, burst)
        return self.buckets[key]

    def _get_window(self, key: str, max_requests: int) -> SlidingWindowCounter:
        if key not in self.windows:
            self.windows[key] = SlidingWindowCounter(1, max_requests)
        return self.windows[key]

    # ------------------------------------------------------------------

    def add_rule(self, rule: RateLimitRule) -> str:
        with self._lock:
            if len(self.rules) >= self.config.max_rules:
                self._cleanup_expired_rules()

            # FIX BUG-7: _generate_rule_id() runs here, inside the lock.
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
        with self._lock:
            if rule_id not in self.rules:
                return False
            del self.rules[rule_id]
            prefix = f"{rule_id}:"
            for key in [k for k in self.buckets if k.startswith(prefix)]:
                del self.buckets[key]
            for key in [k for k in self.windows if k.startswith(prefix)]:
                del self.windows[key]
            self.stats['active_limits'] = len(self.rules)
            logger.info(f"Removed rate limit rule: {rule_id}")
            return True

    def _cleanup_expired_rules(self) -> None:
        expired = [rid for rid, rule in self.rules.items() if rule.is_expired()]
        for rule_id in expired:
            self.remove_rule(rule_id)
            self.stats['rules_expired'] += 1
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired rate limit rules")

    def _cleanup_loop(self) -> None:
        """Background cleanup - uses Event.wait() so stop() is responsive."""
        while not self._stop_event.wait(timeout=self.config.rule_cleanup_interval):
            # FIX BUG-12: Event.wait(timeout) returns True if stop was signalled
            # (exits loop immediately) or False on timeout (runs cleanup).
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
        Return True if traffic is allowed, False if it should be dropped.

        FIX BUG-10: The original iterated self.rules.values() without holding
        _lock.  A concurrent add_rule() or _cleanup_loop could mutate the dict
        mid-iteration to RuntimeError.  Now iterates a shallow copy so the lock
        is not held for the entire (potentially slow) bucket/window check.
        """
        with self._lock:
            active_rules = list(self.rules.values())   # FIX BUG-10: copy

        allowed = True

        for rule in active_rules:
            if not rule.matches(ip, protocol, port):
                continue

            key = self._rate_state_key(rule, ip, protocol)

            if rule.limit_type == LimitType.PACKET:
                if self.config.use_sliding_window:
                    if not self._get_window(key, int(rule.limit_value)).allow_request():
                        allowed = False
                else:
                    if not self._get_bucket(key, rule.limit_value, rule.burst_value).consume(packets):
                        allowed = False

            elif rule.limit_type == LimitType.BYTE:
                if not self._get_bucket(key, rule.limit_value, rule.burst_value).consume(bytes_count):
                    allowed = False

            elif rule.limit_type == LimitType.CONNECTION:
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

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def rate_limit_ip(
        self,
        ip: str,
        rate_pps: Optional[int] = None,
        duration_seconds: int = 300,
    ) -> Optional[str]:
        """Apply packet-rate limiting to a specific IP."""
        rate = float(rate_pps or self.config.default_packet_rate)
        # FIX BUG-8: apply burst_multiplier (was rate==burst, ignoring config).
        burst = rate * self.config.default_burst_multiplier
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=rate,
            burst_value=burst,   # FIX BUG-8
            target_ip=ip,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_subnet(
        self,
        subnet: str,
        rate_pps: Optional[int] = None,
        duration_seconds: int = 300,
    ) -> Optional[str]:
        """Apply packet-rate limiting to a subnet."""
        rate = float(rate_pps or self.config.default_packet_rate)
        burst = rate * self.config.default_burst_multiplier   # FIX BUG-8
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=rate,
            burst_value=burst,
            target_subnet=subnet,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_protocol(
        self,
        protocol: int,
        rate_pps: int,
        duration_seconds: int = 300,
    ) -> Optional[str]:
        burst = float(rate_pps) * self.config.default_burst_multiplier
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.PACKET,
            limit_value=float(rate_pps),
            burst_value=burst,
            protocol=protocol,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def rate_limit_bandwidth(
        self,
        ip: str,
        bps: int,
        duration_seconds: int = 300,
    ) -> Optional[str]:
        """Apply bandwidth (byte-rate) limiting to an IP."""
        bytes_per_sec = float(bps // 8)
        burst = bytes_per_sec * max(2.0, self.config.default_burst_multiplier)
        rule = RateLimitRule(
            id="",
            limit_type=LimitType.BYTE,
            limit_value=bytes_per_sec,
            burst_value=burst,
            target_ip=ip,
            duration_seconds=duration_seconds,
        )
        return self.add_rule(rule)

    def get_active_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
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
        return {
            **self.stats,
            'active_rules': len(self.rules),
            'active_buckets': len(self.buckets),
            'active_windows': len(self.windows),
            'default_packet_rate': self.config.default_packet_rate,
            'use_sliding_window': self.config.use_sliding_window,
        }

    def stop(self) -> None:
        """Stop the rate limiter and its cleanup thread promptly."""
        # FIX BUG-12: signal the Event so the cleanup thread wakes immediately.
        self._stop_event.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        logger.info("RateLimiter stopped")

    def reset_stats(self) -> None:
        self.stats = {
            'packets_allowed': 0,
            'packets_limited': 0,
            'active_limits': len(self.rules),
            'rules_created': self.stats['rules_created'],
            'rules_expired': self.stats['rules_expired'],
        }


# ==================================================================
# Distributed Rate Limiting Backends
# ==================================================================

class RateLimitingBackend(ABC):
    """Abstract base class for distributed rate limiting backends."""

    @abstractmethod
    def check_rate_limit(
        self, key: str, limit: int, window_seconds: int, algorithm: "RateLimiterAlgorithm"
    ) -> bool:
        """
        Checks if a request is allowed under the given rate limit.
        Returns True if the request is allowed, False otherwise.
        """
        pass

    def connect(self, **kwargs) -> None:
        """Optional connection method."""
        pass

    def disconnect(self) -> None:
        """Optional disconnection method."""
        pass


class MemoryBackend(RateLimitingBackend):
    """
    In-memory backend for testing or single-node use.
    Not suitable for a distributed environment.
    """
    def __init__(self):
        self.windows = defaultdict(lambda: deque())
        self.fixed_counters = defaultdict(lambda: (0, 0)) # (count, expiry_timestamp)
        self._lock = threading.Lock()

    def check_rate_limit(
        self, key: str, limit: int, window_seconds: int, algorithm: "RateLimiterAlgorithm"
    ) -> bool:
        if algorithm == RateLimiterAlgorithm.FIXED_WINDOW:
            return self._check_fixed_window(key, limit, window_seconds)
        if algorithm == RateLimiterAlgorithm.SLIDING_WINDOW_LOG:
            return self._check_sliding_window_log(key, limit, window_seconds)
        logger.warning(f"MemoryBackend does not support algorithm: {algorithm}")
        return True

    def _check_fixed_window(self, key: str, limit: int, window_seconds: int) -> bool:
        with self._lock:
            now = time.time()
            count, expiry = self.fixed_counters[key]

            if now > expiry:
                self.fixed_counters[key] = (1, now + window_seconds)
                return True
            
            if count < limit:
                self.fixed_counters[key] = (count + 1, expiry)
                return True
            
            return False

    def _check_sliding_window_log(self, key: str, limit: int, window_seconds: int) -> bool:
        with self._lock:
            now = time.time()
            window = self.windows[key]
            cutoff = now - window_seconds
            
            while window and window[0] < cutoff:
                window.popleft()
            
            if len(window) < limit:
                window.append(now)
                return True
            
            return False


class RedisBackend(RateLimitingBackend):
    """Distributed rate limiting backend using Redis."""

    # Lua script: atomic INCR + conditional EXPIRE in a single round-trip.
    _INCR_EXPIRE_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return current
    """

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
    ):
        self.redis_client: Any = None
        self._init_redis(redis_host, redis_port, redis_password)

    def _init_redis(self, host: str, port: int, password: Optional[str]) -> None:
        try:
            import redis as redis_lib  # type: ignore
            self.redis_client = redis_lib.Redis(
                host=host,
                port=port,
                password=password,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            self.redis_client.ping()
            logger.info("RedisBackend: Redis connection established")
        except ImportError:
            logger.error("RedisBackend: 'redis' package not installed. This backend is unusable.")
            self.redis_client = None
        except Exception as exc:
            logger.error(f"RedisBackend: Failed to connect to Redis: {exc}")
            self.redis_client = None

    def check_rate_limit(
        self, key: str, limit: int, window_seconds: int, algorithm: "RateLimiterAlgorithm"
    ) -> bool:
        if not self.redis_client:
            logger.warning("RedisBackend not connected, failing open.")
            return True

        if algorithm == RateLimiterAlgorithm.FIXED_WINDOW:
            return self._check_fixed_window(key, limit, window_seconds)
        if algorithm == RateLimiterAlgorithm.SLIDING_WINDOW_LOG:
            return self._check_sliding_window_log(key, limit, window_seconds)
        
        logger.warning(f"RedisBackend does not support algorithm: {algorithm}")
        return True

    def _check_fixed_window(self, key: str, limit: int, window_seconds: int) -> bool:
        try:
            current = self.redis_client.eval(
                self._INCR_EXPIRE_SCRIPT,
                1,
                key,
                window_seconds,
            )
            return int(current) <= limit
        except Exception as exc:
            logger.error(f"Redis fixed window check failed: {exc}")
            return True   # fail open

    def _check_sliding_window_log(self, key: str, limit: int, window_seconds: int) -> bool:
        try:
            now = time.time()
            
            pipeline = self.redis_client.pipeline()
            pipeline.zremrangebyscore(key, 0, now - window_seconds)
            pipeline.zadd(key, {f"{now}-{random.random()}": now})
            pipeline.zcard(key)
            pipeline.expire(key, window_seconds)
            results = pipeline.execute()

            current_count = results[2]
            return current_count <= limit
        except Exception as exc:
            logger.error(f"Redis Sliding Window Log check failed: {exc}")
            return True  # Fail open


class DistributedRateLimiter(RateLimiter):
    """
    Distributed rate limiter using a pluggable backend for cross-instance coordination.
    This class maintains backward compatibility by creating a RedisBackend by default.
    For more flexibility, you can instantiate a backend and pass it to the constructor.
    """

    def __init__(
        self,
        config: RateLimiterConfig,
        backend: Optional[RateLimitingBackend] = None,
        # The following are for backward compatibility / direct Redis instantiation
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
    ) -> None:
        super().__init__(config)
        if backend:
            self.backend = backend
        else:
            self.backend = RedisBackend(
                redis_host=redis_host,
                redis_port=redis_port,
                redis_password=redis_password,
            )
        logger.info(f"DistributedRateLimiter initialised with backend: {self.backend.__class__.__name__}")

    def check_rate_limit_distributed(
        self,
        ip: str,
        limit_key: str,
        limit_value: int,
        window_seconds: int = 1,
        algorithm: "RateLimiterAlgorithm" = RateLimiterAlgorithm.FIXED_WINDOW,
    ) -> bool:
        """
        Check rate limit using the configured distributed backend.
        """
        if not self.backend:
            logger.warning("No distributed backend configured, rate limit check is ineffective.")
            return True # Fail open

        try:
            key = f"rate_limit:{limit_key}:{ip}"
            
            allowed = self.backend.check_rate_limit(
                key=key,
                limit=limit_value,
                window_seconds=window_seconds,
                algorithm=algorithm
            )

            if allowed:
                self.stats['packets_allowed'] += 1
            else:
                self.stats['packets_limited'] += 1
            
            return allowed

        except Exception as exc:
            logger.error(f"Distributed rate limit check failed with backend: {exc}")
            return True   # fail open