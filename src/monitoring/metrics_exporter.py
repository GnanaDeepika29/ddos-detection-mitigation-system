"""
Metrics Exporter Module

Exports DDoS detection metrics to Prometheus for real-time monitoring.
Supports counter, gauge, histogram, and summary metric types.
"""

import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable
from collections import defaultdict
import logging

# Lazy import for prometheus client
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, Info,
        generate_latest, CONTENT_TYPE_LATEST,
    )
    from prometheus_client.core import CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logging.warning("prometheus_client not available. Install with: pip install prometheus-client")

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of Prometheus metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    INFO = "info"


@dataclass
class MetricsConfig:
    """Configuration for metrics exporter"""
    enabled: bool = True
    port: int = 9091
    endpoint: str = "/metrics"
    namespace: str = "ddos_protection"
    subsystem: str = "detection"

    collection_interval_seconds: int = 15
    cleanup_interval_seconds: int = 60

    enable_detection_metrics: bool = True
    enable_traffic_metrics: bool = True
    enable_mitigation_metrics: bool = True
    enable_system_metrics: bool = True

    latency_buckets: List[float] = field(default_factory=lambda: [
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
    ])

    packet_size_buckets: List[float] = field(default_factory=lambda: [
        64, 128, 256, 512, 1024, 1500, 4096, 8192, 16384
    ])


class MetricsExporter:
    """
    Prometheus metrics exporter for DDoS detection system.
    Provides real-time metrics for monitoring and alerting.
    """

    def __init__(self, config: Optional[MetricsConfig] = None):
        if not PROMETHEUS_AVAILABLE:
            raise ImportError("prometheus_client is required for metrics export")
            
        self.config = config or MetricsConfig()
        self.registry = CollectorRegistry()

        # Detection metrics
        self.detection_counter = None
        self.false_positive_counter = None
        self.detection_latency = None
        self.detection_confidence = None

        # Traffic metrics
        self.packets_per_second = None
        self.bytes_per_second = None
        self.flows_per_second = None
        self.packet_size_distribution = None
        self.entropy_src_ip = None
        self.entropy_dst_ip = None

        # Attack metrics
        self.attack_counter = None
        self.attack_duration = None
        self.attack_intensity = None
        self.alerts_total = None
        self.top_src_ip_packets = None
        self.top_dst_ip_packets = None

        # Mitigation metrics
        self.mitigation_actions_counter = None
        self.rate_limited_packets = None
        self.blocked_ips = None
        self.active_rules = None

        # System metrics
        self.cpu_usage = None
        self.memory_usage = None
        self.kafka_lag = None
        self.processing_latency = None

        self._custom_metrics: Dict[str, Any] = {}
        self._metric_lock = threading.Lock()
        self._http_server: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None

        self._init_metrics()

        logger.info(f"MetricsExporter initialized on port {self.config.port}")

    def _init_metrics(self):
        """Initialize all Prometheus metrics"""
        ns = self.config.namespace
        ss = self.config.subsystem

        if self.config.enable_detection_metrics:
            self.detection_counter = Counter(
                f"{ns}_{ss}_detections_total",
                "Total number of DDoS detections",
                ["attack_type", "severity"],
                registry=self.registry,
            )

            self.false_positive_counter = Counter(
                f"{ns}_{ss}_false_positives_total",
                "Total number of false positives",
                registry=self.registry,
            )

            self.detection_latency = Histogram(
                f"{ns}_{ss}_detection_latency_seconds",
                "Detection latency in seconds",
                buckets=self.config.latency_buckets,
                registry=self.registry,
            )

            self.detection_confidence = Gauge(
                f"{ns}_{ss}_detection_confidence",
                "Detection confidence score",
                ["attack_type"],
                registry=self.registry,
            )

        if self.config.enable_traffic_metrics:
            self.packets_per_second = Gauge(
                f"{ns}_{ss}_packets_per_second",
                "Packets per second",
                ["direction"],
                registry=self.registry,
            )

            self.bytes_per_second = Gauge(
                f"{ns}_{ss}_bytes_per_second",
                "Bytes per second",
                ["direction"],
                registry=self.registry,
            )

            self.flows_per_second = Gauge(
                f"{ns}_{ss}_flows_per_second",
                "Flows per second",
                registry=self.registry,
            )

            self.packet_size_distribution = Histogram(
                f"{ns}_{ss}_packet_size_bytes",
                "Packet size distribution",
                buckets=self.config.packet_size_buckets,
                registry=self.registry,
            )

            self.entropy_src_ip = Gauge(
                f"{ns}_{ss}_entropy_src_ip",
                "Source IP entropy (lower = more concentrated)",
                registry=self.registry,
            )

            self.entropy_dst_ip = Gauge(
                f"{ns}_{ss}_entropy_dst_ip",
                "Destination IP entropy",
                registry=self.registry,
            )

        # Attack metrics
        self.attack_counter = Counter(
            f"{ns}_{ss}_attacks_total",
            "Total number of attacks detected",
            ["attack_type"],
            registry=self.registry,
        )

        self.attack_duration = Histogram(
            f"{ns}_{ss}_attack_duration_seconds",
            "Duration of attacks in seconds",
            buckets=[5, 10, 30, 60, 120, 300, 600, 1800, 3600],
            registry=self.registry,
        )

        self.attack_intensity = Gauge(
            f"{ns}_{ss}_attack_intensity",
            "Attack intensity (packets per second)",
            ["attack_type"],
            registry=self.registry,
        )

        self.alerts_total = Counter(
            f"{ns}_{ss}_alerts_total",
            "Total alerts raised",
            ["severity", "attack_type"],
            registry=self.registry,
        )

        self.top_src_ip_packets = Gauge(
            f"{ns}_{ss}_top_src_ips",
            "Packet count for top source IPs",
            ["src_ip"],
            registry=self.registry,
        )

        self.top_dst_ip_packets = Gauge(
            f"{ns}_{ss}_top_dst_ips",
            "Packet count for top destination IPs",
            ["dst_ip"],
            registry=self.registry,
        )

        if self.config.enable_mitigation_metrics:
            self.mitigation_actions_counter = Counter(
                f"{ns}_{ss}_mitigation_actions_total",
                "Total mitigation actions taken",
                ["action_type", "success"],
                registry=self.registry,
            )

            self.rate_limited_packets = Counter(
                f"{ns}_{ss}_rate_limited_packets_total",
                "Total packets rate limited",
                ["target_ip"],
                registry=self.registry,
            )

            self.blocked_ips = Gauge(
                f"{ns}_{ss}_blocked_ips",
                "Number of currently blocked IPs",
                registry=self.registry,
            )

            self.active_rules = Gauge(
                f"{ns}_{ss}_active_rules",
                "Number of active mitigation rules",
                ["rule_type"],
                registry=self.registry,
            )

        if self.config.enable_system_metrics:
            self.cpu_usage = Gauge(
                f"{ns}_{ss}_cpu_usage_percent",
                "CPU usage percentage",
                ["core"],
                registry=self.registry,
            )

            self.memory_usage = Gauge(
                f"{ns}_{ss}_memory_usage_bytes",
                "Memory usage in bytes",
                ["type"],
                registry=self.registry,
            )

            self.kafka_lag = Gauge(
                f"{ns}_{ss}_kafka_consumer_lag",
                "Kafka consumer lag",
                ["topic", "consumer_group"],
                registry=self.registry,
            )

            self.processing_latency = Histogram(
                f"{ns}_{ss}_processing_latency_seconds",
                "Flow processing latency",
                buckets=self.config.latency_buckets,
                registry=self.registry,
            )

    # ==================== Detection Metrics ====================

    def record_detection(self, attack_type: str, severity: str):
        """Record a DDoS detection"""
        if self.detection_counter:
            self.detection_counter.labels(attack_type=attack_type, severity=severity).inc()

    def record_false_positive(self):
        """Record a false positive"""
        if self.false_positive_counter:
            self.false_positive_counter.inc()

    def record_detection_latency(self, latency_seconds: float):
        """Record detection latency"""
        if self.detection_latency:
            self.detection_latency.observe(latency_seconds)

    def set_detection_confidence(self, attack_type: str, confidence: float):
        """Set detection confidence score"""
        if self.detection_confidence:
            self.detection_confidence.labels(attack_type=attack_type).set(confidence)

    # ==================== Traffic Metrics ====================

    def set_packets_per_second(self, pps: float, direction: str = "total"):
        """Set packets per second metric"""
        if self.packets_per_second:
            self.packets_per_second.labels(direction=direction).set(pps)

    def set_bytes_per_second(self, bps: float, direction: str = "total"):
        """Set bytes per second metric"""
        if self.bytes_per_second:
            self.bytes_per_second.labels(direction=direction).set(bps)

    def set_flows_per_second(self, fps: float):
        """Set flows per second metric"""
        if self.flows_per_second:
            self.flows_per_second.set(fps)

    def record_packet_size(self, size_bytes: int):
        """Record packet size for distribution"""
        if self.packet_size_distribution:
            self.packet_size_distribution.observe(size_bytes)

    def set_entropy_src_ip(self, entropy: float):
        """Set source IP entropy metric"""
        if self.entropy_src_ip:
            self.entropy_src_ip.set(entropy)

    def set_entropy_dst_ip(self, entropy: float):
        """Set destination IP entropy metric"""
        if self.entropy_dst_ip:
            self.entropy_dst_ip.set(entropy)

    # ==================== Attack Metrics ====================

    def record_attack(self, attack_type: str):
        """Record an attack detection"""
        if self.attack_counter:
            self.attack_counter.labels(attack_type=attack_type).inc()

    def record_attack_duration(self, duration_seconds: float):
        """Record attack duration"""
        if self.attack_duration:
            self.attack_duration.observe(duration_seconds)

    def set_attack_intensity(self, attack_type: str, intensity_pps: float):
        """Set attack intensity"""
        if self.attack_intensity:
            self.attack_intensity.labels(attack_type=attack_type).set(intensity_pps)

    def record_alert(self, severity: str, attack_type: str = "unknown"):
        """Record an alert"""
        if self.alerts_total:
            self.alerts_total.labels(severity=severity, attack_type=attack_type).inc()

    def update_top_src_ips(self, ip_counts: Dict[str, int]):
        """Update top source IP metrics"""
        if self.top_src_ip_packets:
            # Clear existing metrics (prometheus doesn't support deletion)
            # Instead, we update with new values
            for ip, count in ip_counts.items():
                # Sanitize IP for label (replace dots with underscores)
                safe_ip = ip.replace('.', '_').replace(':', '_')
                self.top_src_ip_packets.labels(src_ip=safe_ip).set(count)

    def update_top_dst_ips(self, ip_counts: Dict[str, int]):
        """Update top destination IP metrics"""
        if self.top_dst_ip_packets:
            for ip, count in ip_counts.items():
                safe_ip = ip.replace('.', '_').replace(':', '_')
                self.top_dst_ip_packets.labels(dst_ip=safe_ip).set(count)

    # ==================== Mitigation Metrics ====================

    def record_mitigation_action(self, action_type: str, success: bool):
        """Record a mitigation action"""
        if self.mitigation_actions_counter:
            self.mitigation_actions_counter.labels(
                action_type=action_type,
                success="true" if success else "false",
            ).inc()

    def record_rate_limited_packets(self, count: int, target_ip: str = ""):
        """Record rate-limited packets"""
        if self.rate_limited_packets:
            safe_ip = target_ip.replace('.', '_').replace(':', '_') if target_ip else "all"
            self.rate_limited_packets.labels(target_ip=safe_ip).inc(count)

    def set_blocked_ips(self, count: int):
        """Set number of blocked IPs"""
        if self.blocked_ips:
            self.blocked_ips.set(count)

    def set_active_rules(self, rule_count: int, rule_type: str = "all"):
        """Set number of active mitigation rules"""
        if self.active_rules:
            self.active_rules.labels(rule_type=rule_type).set(rule_count)

    # ==================== System Metrics ====================

    def set_cpu_usage(self, usage_percent: float, core: str = "total"):
        """Set CPU usage metric"""
        if self.cpu_usage:
            self.cpu_usage.labels(core=core).set(usage_percent)

    def set_memory_usage(self, bytes_used: int, mem_type: str = "rss"):
        """Set memory usage metric"""
        if self.memory_usage:
            self.memory_usage.labels(type=mem_type).set(bytes_used)

    def set_kafka_lag(self, lag: int, topic: str, consumer_group: str):
        """Set Kafka consumer lag"""
        if self.kafka_lag:
            self.kafka_lag.labels(topic=topic, consumer_group=consumer_group).set(lag)

    def record_processing_latency(self, latency_seconds: float):
        """Record processing latency"""
        if self.processing_latency:
            self.processing_latency.observe(latency_seconds)

    # ==================== Custom Metrics ====================

    def set_custom_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Create or update a custom gauge metric"""
        metric_name = f"{self.config.namespace}_{name}"

        with self._metric_lock:
            if metric_name not in self._custom_metrics:
                label_names = sorted(labels.keys()) if labels else []
                self._custom_metrics[metric_name] = Gauge(
                    metric_name,
                    f"Custom metric: {name}",
                    labelnames=label_names,
                    registry=self.registry,
                )

            gauge = self._custom_metrics[metric_name]

        if labels:
            gauge.labels(**labels).set(value)
        else:
            gauge.set(value)

    def increment_custom_counter(self, name: str, labels: Optional[Dict[str, str]] = None):
        """Create or increment a custom counter metric"""
        metric_name = f"{self.config.namespace}_{name}"

        with self._metric_lock:
            if metric_name not in self._custom_metrics:
                label_names = sorted(labels.keys()) if labels else []
                self._custom_metrics[metric_name] = Counter(
                    metric_name,
                    f"Custom metric: {name}",
                    labelnames=label_names,
                    registry=self.registry,
                )

            counter = self._custom_metrics[metric_name]

        if labels:
            counter.labels(**labels).inc()
        else:
            counter.inc()

    # ==================== Utility Methods ====================

    def get_metrics(self) -> bytes:
        """Get current metrics in Prometheus format"""
        return generate_latest(self.registry)

    def get_metrics_content_type(self) -> str:
        """Get content type for metrics response"""
        return CONTENT_TYPE_LATEST

    def reset_metrics(self):
        """Reset all metrics"""
        self.registry = CollectorRegistry()
        self._custom_metrics.clear()
        self._init_metrics()
        logger.info("All metrics reset")

    def get_stats(self) -> Dict[str, Any]:
        """Get exporter statistics"""
        return {
            'enabled': self.config.enabled,
            'port': self.config.port,
            'endpoint': self.config.endpoint,
            'namespace': self.config.namespace,
            'detection_enabled': self.config.enable_detection_metrics,
            'traffic_enabled': self.config.enable_traffic_metrics,
            'mitigation_enabled': self.config.enable_mitigation_metrics,
            'system_enabled': self.config.enable_system_metrics,
            'custom_metrics_count': len(self._custom_metrics),
        }

    def start_http_server(self, host: str = "0.0.0.0") -> None:
        """Expose metrics via a lightweight HTTP server."""
        if not self.config.enabled or self._http_server is not None:
            return

        exporter = self
        endpoint = self.config.endpoint

        class _MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != endpoint:
                    self.send_response(404)
                    self.end_headers()
                    return

                payload = exporter.get_metrics()
                self.send_response(200)
                self.send_header("Content-Type", exporter.get_metrics_content_type())
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                logger.debug("Metrics HTTP server: " + format, *args)

        self._http_server = ThreadingHTTPServer((host, self.config.port), _MetricsHandler)
        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever,
            daemon=True,
            name=f"metrics-server-{self.config.port}",
        )
        self._http_thread.start()
        logger.info("Metrics HTTP server started on %s:%s%s", host, self.config.port, endpoint)

    def stop_http_server(self) -> None:
        """Stop the lightweight metrics HTTP server."""
        if self._http_server is None:
            return
        self._http_server.shutdown()
        self._http_server.server_close()
        if self._http_thread:
            self._http_thread.join(timeout=5)
        self._http_server = None
        self._http_thread = None
        logger.info("Metrics HTTP server stopped")


class MetricCollector:
    """Background metric collector that periodically updates system metrics"""

    def __init__(self, metrics_exporter: MetricsExporter, collection_interval: int = 15):
        self.metrics_exporter = metrics_exporter
        self.collection_interval = collection_interval
        self._running = False
        self._thread = None
        self._collectors: List[Callable] = []
        logger.info(f"MetricCollector initialized with interval {collection_interval}s")

    def register_collector(self, collector: Callable):
        """Register a custom metric collector function"""
        self._collectors.append(collector)

    def _collect_system_metrics(self):
        """Collect system metrics using psutil"""
        try:
            import psutil

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.metrics_exporter.set_cpu_usage(cpu_percent, "total")

            for i, core_percent in enumerate(psutil.cpu_percent(percpu=True)):
                self.metrics_exporter.set_cpu_usage(core_percent, f"core_{i}")

            # Memory usage
            memory = psutil.virtual_memory()
            self.metrics_exporter.set_memory_usage(memory.used, "system_used")
            self.metrics_exporter.set_memory_usage(memory.available, "system_available")

            # Process memory
            process = psutil.Process()
            self.metrics_exporter.set_memory_usage(process.memory_info().rss, "process_rss")

        except ImportError:
            logger.debug("psutil not installed, system metrics disabled")
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")

    def _run(self):
        """Background collection loop"""
        while self._running:
            try:
                if self.metrics_exporter.config.enable_system_metrics:
                    self._collect_system_metrics()

                for collector in self._collectors:
                    try:
                        collector()
                    except Exception as e:
                        logger.error(f"Custom collector failed: {e}")

            except Exception as e:
                logger.error(f"Metric collection failed: {e}")

            time.sleep(self.collection_interval)

    def start(self):
        """Start background metric collection"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("MetricCollector started")

    def stop(self):
        """Stop background metric collection"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("MetricCollector stopped")
