"""
Time-Window Aggregator Module

Aggregates network flows over sliding time windows for feature extraction.
"""

import time
import math
import logging
import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TimeWindow:
    """Represents a time window of aggregated flows"""
    start_time: float
    end_time: float
    flows: List[Dict[str, Any]] = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    unique_src_ips: Set[str] = field(default_factory=set)
    unique_dst_ips: Set[str] = field(default_factory=set)
    protocol_counts: Dict[int, int] = field(default_factory=dict)
    src_ip_counts: Dict[str, int] = field(default_factory=dict)
    dst_ip_counts: Dict[str, int] = field(default_factory=dict)
    packet_size_distribution: List[int] = field(default_factory=list)
    src_port_counts: Dict[int, int] = field(default_factory=dict)
    dst_port_counts: Dict[int, int] = field(default_factory=dict)

    def add_flow(self, flow: Dict[str, Any]):
        """Add a flow to the window"""
        self.flows.append(flow)
        self.total_packets += flow.get('total_packets', flow.get('packets', 1))
        self.total_bytes += flow.get('total_bytes', flow.get('bytes', 0))

        src_ip = flow.get('ip_src')
        dst_ip = flow.get('ip_dst')
        src_port = flow.get('sport', 0)
        dst_port = flow.get('dport', 0)

        if src_ip:
            self.unique_src_ips.add(src_ip)
            weight = flow.get('total_packets', flow.get('packets', 1)) or 1
            self.src_ip_counts[src_ip] = self.src_ip_counts.get(src_ip, 0) + weight

        if dst_ip:
            self.unique_dst_ips.add(dst_ip)
            weight = flow.get('total_packets', flow.get('packets', 1)) or 1
            self.dst_ip_counts[dst_ip] = self.dst_ip_counts.get(dst_ip, 0) + weight

        if src_port:
            weight = flow.get('total_packets', flow.get('packets', 1)) or 1
            self.src_port_counts[src_port] = self.src_port_counts.get(src_port, 0) + weight

        if dst_port:
            weight = flow.get('total_packets', flow.get('packets', 1)) or 1
            self.dst_port_counts[dst_port] = self.dst_port_counts.get(dst_port, 0) + weight

        protocol = flow.get('protocol', 0)
        weight = flow.get('total_packets', flow.get('packets', 1)) or 1
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + weight

        avg_packet_size = flow.get('avg_packet_size', 0)
        if avg_packet_size > 0:
            self.packet_size_distribution.append(int(avg_packet_size))

    @property
    def duration(self) -> float:
        """Window duration in seconds"""
        return self.end_time - self.start_time

    @property
    def packets_per_second(self) -> float:
        """Packets per second in this window"""
        return self.total_packets / self.duration if self.duration > 0 else 0

    @property
    def bytes_per_second(self) -> float:
        """Bytes per second in this window"""
        return self.total_bytes / self.duration if self.duration > 0 else 0

    @property
    def entropy_src_ip(self) -> float:
        """Calculate entropy of source IPs (lower = more concentrated)"""
        if not self.src_ip_counts:
            return 0
        total = sum(self.src_ip_counts.values())
        entropy = 0.0
        for count in self.src_ip_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @property
    def entropy_dst_ip(self) -> float:
        """Calculate entropy of destination IPs"""
        if not self.dst_ip_counts:
            return 0
        total = sum(self.dst_ip_counts.values())
        entropy = 0.0
        for count in self.dst_ip_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @property
    def packets_per_ip(self) -> float:
        """Average packets per source IP"""
        if not self.unique_src_ips:
            return 0
        return self.total_packets / len(self.unique_src_ips)

    def to_dict(self) -> Dict[str, Any]:
        """Convert window to dictionary"""
        tcp_flag_counts = {
            'syn': sum(flow.get('tcp_syn_count', 0) for flow in self.flows),
            'rst': sum(flow.get('tcp_rst_count', 0) for flow in self.flows),
            'fin': sum(flow.get('tcp_fin_count', 0) for flow in self.flows),
        }
        return {
            'window_start': self.start_time,
            'window_end': self.end_time,
            'duration': self.duration,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'unique_src_ips': len(self.unique_src_ips),
            'unique_dst_ips': len(self.unique_dst_ips),
            'entropy_src_ip': self.entropy_src_ip,
            'entropy_dst_ip': self.entropy_dst_ip,
            'packets_per_ip': self.packets_per_ip,
            'flows': list(self.flows),
            'flows_count': len(self.flows),
            'protocol_counts': dict(self.protocol_counts),
            'protocol_distribution': dict(self.protocol_counts),
            'src_ip_counts': dict(self.src_ip_counts),
            'dst_ip_counts': dict(self.dst_ip_counts),
            'top_src_ips': sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_dst_ips': sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_src_ports': sorted(self.src_port_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_dst_ports': sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'packet_size_distribution': list(self.packet_size_distribution),
            'tcp_flag_counts': tcp_flag_counts,
            'avg_packet_size': sum(self.packet_size_distribution) / len(self.packet_size_distribution) if self.packet_size_distribution else 0,
        }


@dataclass
class AggregatedStats:
    """Aggregated statistics with anomaly detection"""
    timestamp: float
    window_size_seconds: int
    metrics: Dict[str, Any] = field(default_factory=dict)
    rolling_mean_packets: float = 0
    rolling_std_packets: float = 0
    rolling_mean_bytes: float = 0
    rolling_std_bytes: float = 0
    rolling_mean_entropy: float = 0
    rolling_std_entropy: float = 0
    is_anomaly_packet_rate: bool = False
    is_anomaly_entropy: bool = False
    anomaly_score: float = 0

    def check_anomalies(self, threshold_multiplier: float = 3.0) -> Dict[str, Any]:
        """Check for anomalies in the aggregated statistics"""
        anomalies = {}
        
        # Check packet rate anomaly
        if self.rolling_std_packets > 0:
            packet_rate = self.metrics.get('packets_per_second', 0)
            z_score = abs(packet_rate - self.rolling_mean_packets) / self.rolling_std_packets
            if z_score > threshold_multiplier:
                anomalies['packet_rate'] = {
                    'is_anomaly': True, 
                    'z_score': z_score,
                    'value': packet_rate,
                    'mean': self.rolling_mean_packets,
                    'std': self.rolling_std_packets
                }
                self.is_anomaly_packet_rate = True
                self.anomaly_score = max(self.anomaly_score, z_score)
        
        # Check entropy anomaly (low entropy may indicate DDoS)
        if self.rolling_std_entropy > 0:
            entropy = self.metrics.get('entropy_src_ip', 0)
            z_score = abs(entropy - self.rolling_mean_entropy) / self.rolling_std_entropy
            # Low entropy is suspicious (negative z-score)
            if entropy < self.rolling_mean_entropy - threshold_multiplier * self.rolling_std_entropy:
                anomalies['entropy'] = {
                    'is_anomaly': True,
                    'z_score': -z_score,
                    'value': entropy,
                    'mean': self.rolling_mean_entropy,
                    'std': self.rolling_std_entropy
                }
                self.is_anomaly_entropy = True
                self.anomaly_score = max(self.anomaly_score, z_score)
        
        return anomalies


class WindowAggregator:
    """Aggregates flows over multiple time windows with rolling statistics"""
    
    def __init__(
        self,
        window_sizes: Optional[List[int]] = None,
        history_size: int = 100,
        enable_rolling_stats: bool = True,
    ):
        self.window_sizes = window_sizes or [1, 5, 10, 60]
        self.history_size = history_size
        self.enable_rolling_stats = enable_rolling_stats
        self.window_history: Dict[int, deque] = {}
        self.rolling_stats: Dict[int, deque] = {}
        self.current_windows: Dict[str, TimeWindow] = {}
        self._last_flow_counters: Dict[str, Dict[str, int]] = {}

        for size in self.window_sizes:
            self.window_history[size] = deque(maxlen=self.history_size)
            self.rolling_stats[size] = deque(maxlen=self.history_size)

        self._last_cleanup = time.time()
        self._active_bucket_start: Dict[int, float] = {}
        
        logger.info(f"WindowAggregator initialized with window sizes: {self.window_sizes}")

    def _get_window(self, window_size: int, current_time: float) -> TimeWindow:
        """Get or create window for given size and time"""
        window_start = math.floor(current_time / window_size) * window_size
        window_key = f"{window_size}_{window_start}"

        if window_key not in self.current_windows:
            new_window = TimeWindow(
                start_time=window_start, 
                end_time=window_start + window_size
            )
            self.current_windows[window_key] = new_window
            self.window_history[window_size].append(new_window)
            self._cleanup_windows(current_time)

        return self.current_windows[window_key]

    def _cleanup_windows(self, current_time: float):
        """Remove expired windows"""
        to_remove = [
            key for key, window in self.current_windows.items() 
            if current_time > window.end_time + 60
        ]
        for key in to_remove:
            del self.current_windows[key]

    def _to_int_counter(self, value: Any) -> int:
        """Convert numeric-ish values to safe integer counters."""
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def _build_delta_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert cumulative flow snapshots into per-update deltas."""
        flow_id = flow.get('flow_id')
        if not flow_id:
            return dict(flow)

        current = {
            'total_packets': self._to_int_counter(flow.get('total_packets', flow.get('packets', 0))),
            'total_bytes': self._to_int_counter(flow.get('total_bytes', flow.get('bytes', 0))),
            'tcp_syn_count': self._to_int_counter(flow.get('tcp_syn_count', 0)),
            'tcp_rst_count': self._to_int_counter(flow.get('tcp_rst_count', 0)),
            'tcp_fin_count': self._to_int_counter(flow.get('tcp_fin_count', 0)),
        }
        previous = self._last_flow_counters.get(flow_id)

        if previous is None or any(current[key] < previous.get(key, 0) for key in current):
            delta = current
        else:
            delta = {key: current[key] - previous.get(key, 0) for key in current}

        self._last_flow_counters[flow_id] = current

        if not any(delta.values()):
            return None

        delta_flow = dict(flow)
        delta_flow['total_packets'] = delta['total_packets']
        delta_flow['packets'] = delta['total_packets']
        delta_flow['total_bytes'] = delta['total_bytes']
        delta_flow['bytes'] = delta['total_bytes']
        delta_flow['tcp_syn_count'] = delta['tcp_syn_count']
        delta_flow['tcp_rst_count'] = delta['tcp_rst_count']
        delta_flow['tcp_fin_count'] = delta['tcp_fin_count']
        return delta_flow

    def _update_rolling_stats(self, window_size: int):
        """Update rolling statistics for a window size"""
        if not self.enable_rolling_stats:
            return

        history = self.window_history[window_size]
        if len(history) < 10:
            return

        # Use recent history for stats
        tail = list(itertools.islice(reversed(history), min(50, len(history))))
        
        packet_rates = [w.packets_per_second for w in tail]
        entropies = [w.entropy_src_ip for w in tail]
        
        mean_packets = sum(packet_rates) / len(packet_rates)
        variance = sum((x - mean_packets) ** 2 for x in packet_rates) / len(packet_rates)
        std_packets = math.sqrt(variance)
        
        mean_entropy = sum(entropies) / len(entropies)
        entropy_variance = sum((x - mean_entropy) ** 2 for x in entropies) / len(entropies)
        std_entropy = math.sqrt(entropy_variance)

        latest_window = history[-1]
        agg_stats = AggregatedStats(
            timestamp=latest_window.end_time,
            window_size_seconds=window_size,
            metrics=latest_window.to_dict(),
            rolling_mean_packets=mean_packets,
            rolling_std_packets=std_packets,
            rolling_mean_entropy=mean_entropy,
            rolling_std_entropy=std_entropy,
        )
        agg_stats.check_anomalies()
        self.rolling_stats[window_size].append(agg_stats)

    def add_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add a flow to all windows and return aggregated stats if window completed"""
        current_time = time.time()
        result = None

        try:
            delta_flow = self._build_delta_flow(flow)
            if delta_flow is None:
                return None

            for size in sorted(self.window_sizes):
                window_start = math.floor(current_time / size) * size
                prev_start = self._active_bucket_start.get(size)

                if prev_start is not None and prev_start != window_start:
                    prev_key = f"{size}_{prev_start}"
                    old = self.current_windows.pop(prev_key, None)
                    if old is not None:
                        self._update_rolling_stats(size)
                        # Return stats for the smallest window
                        if size == min(self.window_sizes) and result is None:
                            if self.rolling_stats[size]:
                                result = dict(self.rolling_stats[size][-1].__dict__)
                            else:
                                agg = AggregatedStats(
                                    timestamp=old.end_time,
                                    window_size_seconds=size,
                                    metrics=old.to_dict(),
                                )
                                result = dict(agg.__dict__)

                window = self._get_window(size, current_time)
                window.add_flow(delta_flow)
                self._active_bucket_start[size] = window_start

            # Periodic cleanup
            if current_time - self._last_cleanup > 60:
                self._cleanup_windows(current_time)
                self._last_cleanup = current_time

            return result

        except Exception as e:
            logger.error(f"Error adding flow to window aggregator: {e}")
            return None

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current statistics for all windows"""
        stats = {}
        for size in self.window_sizes:
            for key, window in self.current_windows.items():
                if key.startswith(f"{size}_"):
                    stats[f"window_{size}s"] = window.to_dict()
                    break
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics"""
        return {
            'window_sizes': self.window_sizes,
            'active_windows': len(self.current_windows),
            'history_size': self.history_size,
            'enabled_rolling_stats': self.enable_rolling_stats,
        }


class RealtimeAggregator:
    """Simple real-time aggregator for single window size"""
    
    def __init__(self, window_size_seconds: int = 5):
        self.window_size = window_size_seconds
        now = time.time()
        self.current_window = TimeWindow(
            start_time=now, 
            end_time=now + window_size_seconds
        )
        self.completed_windows: deque = deque(maxlen=100)

    def add_flow(self, flow: Dict[str, Any]) -> Optional[TimeWindow]:
        """Add flow and return completed window if any"""
        current_time = time.time()

        if current_time >= self.current_window.end_time:
            completed = self.current_window
            self.completed_windows.append(completed)

            self.current_window = TimeWindow(
                start_time=self.current_window.end_time,
                end_time=self.current_window.end_time + self.window_size,
            )
            self.current_window.add_flow(flow)
            return completed

        self.current_window.add_flow(flow)
        return None

    def get_packet_rate(self) -> float:
        """Get current packet rate"""
        return self.current_window.packets_per_second

    def get_entropy(self) -> float:
        """Get current source IP entropy"""
        return self.current_window.entropy_src_ip

    def get_bytes_per_second(self) -> float:
        """Get current bytes per second"""
        return self.current_window.bytes_per_second

    def reset(self):
        """Reset the aggregator"""
        now = time.time()
        self.current_window = TimeWindow(
            start_time=now,
            end_time=now + self.window_size
        )
        self.completed_windows.clear()
