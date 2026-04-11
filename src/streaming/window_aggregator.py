"""
Time-Window Aggregator Module

Aggregates network flows over sliding time windows for feature extraction.
"""

import copy
import itertools
import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class TimeWindow:
    """Represents a discrete time window of aggregated flows."""
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

    def add_flow(self, flow: Dict[str, Any]) -> None:
        """Add a flow to this window, accumulating all counters."""
        self.flows.append(flow)
        weight = flow.get('total_packets', flow.get('packets', 1)) or 1
        self.total_packets += weight
        self.total_bytes += flow.get('total_bytes', flow.get('bytes', 0))

        src_ip = flow.get('ip_src')
        dst_ip = flow.get('ip_dst')
        src_port = flow.get('sport', 0)
        dst_port = flow.get('dport', 0)

        if src_ip:
            self.unique_src_ips.add(src_ip)
            self.src_ip_counts[src_ip] = self.src_ip_counts.get(src_ip, 0) + weight

        if dst_ip:
            self.unique_dst_ips.add(dst_ip)
            self.dst_ip_counts[dst_ip] = self.dst_ip_counts.get(dst_ip, 0) + weight

        if src_port:
            self.src_port_counts[src_port] = (
                self.src_port_counts.get(src_port, 0) + weight
            )

        if dst_port:
            self.dst_port_counts[dst_port] = (
                self.dst_port_counts.get(dst_port, 0) + weight
            )

        protocol = flow.get('protocol', 0)
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + weight

        avg_pkt = flow.get('avg_packet_size', 0)
        if avg_pkt > 0:
            self.packet_size_distribution.append(int(avg_pkt))

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def packets_per_second(self) -> float:
        return self.total_packets / self.duration if self.duration > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        return self.total_bytes / self.duration if self.duration > 0 else 0.0

    @property
    def entropy_src_ip(self) -> float:
        """Shannon entropy of source-IP distribution (lower = more concentrated)."""
        if not self.src_ip_counts:
            return 0.0
        total = sum(self.src_ip_counts.values())
        return -sum(
            (c / total) * math.log2(c / total)
            for c in self.src_ip_counts.values()
            if c > 0
        )

    @property
    def entropy_dst_ip(self) -> float:
        """Shannon entropy of destination-IP distribution."""
        if not self.dst_ip_counts:
            return 0.0
        total = sum(self.dst_ip_counts.values())
        return -sum(
            (c / total) * math.log2(c / total)
            for c in self.dst_ip_counts.values()
            if c > 0
        )

    @property
    def packets_per_ip(self) -> float:
        """Average packets per distinct source IP."""
        if not self.unique_src_ips:
            return 0.0
        return self.total_packets / len(self.unique_src_ips)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the window to a plain dictionary."""
        tcp_flag_counts = {
            'syn': sum(f.get('tcp_syn_count', 0) for f in self.flows),
            'rst': sum(f.get('tcp_rst_count', 0) for f in self.flows),
            'fin': sum(f.get('tcp_fin_count', 0) for f in self.flows),
        }
        psd = self.packet_size_distribution
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
            'top_src_ips': sorted(
                self.src_ip_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'top_dst_ips': sorted(
                self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'top_src_ports': sorted(
                self.src_port_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'top_dst_ports': sorted(
                self.dst_port_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'packet_size_distribution': list(psd),
            'tcp_flag_counts': tcp_flag_counts,
            'avg_packet_size': sum(psd) / len(psd) if psd else 0.0,
        }


@dataclass
class AggregatedStats:
    """Aggregated statistics with anomaly detection for a single completed window."""
    timestamp: float
    window_size_seconds: int
    metrics: Dict[str, Any] = field(default_factory=dict)
    rolling_mean_packets: float = 0.0
    rolling_std_packets: float = 0.0
    rolling_mean_bytes: float = 0.0
    rolling_std_bytes: float = 0.0
    rolling_mean_entropy: float = 0.0
    rolling_std_entropy: float = 0.0
    is_anomaly_packet_rate: bool = False
    is_anomaly_entropy: bool = False
    anomaly_score: float = 0.0

    def check_anomalies(self, threshold_multiplier: float = 3.0) -> Dict[str, Any]:
        """Detect anomalies via z-score and update the anomaly flags in-place."""
        anomalies: Dict[str, Any] = {}

        if self.rolling_std_packets > 0:
            rate = self.metrics.get('packets_per_second', 0.0)
            z = abs(rate - self.rolling_mean_packets) / self.rolling_std_packets
            if z > threshold_multiplier:
                anomalies['packet_rate'] = {
                    'is_anomaly': True,
                    'z_score': z,
                    'value': rate,
                    'mean': self.rolling_mean_packets,
                    'std': self.rolling_std_packets,
                }
                self.is_anomaly_packet_rate = True
                self.anomaly_score = max(self.anomaly_score, z)

        if self.rolling_std_entropy > 0:
            entropy = self.metrics.get('entropy_src_ip', 0.0)
            # Low entropy (concentrated sources) is the anomalous direction.
            if entropy < self.rolling_mean_entropy - threshold_multiplier * self.rolling_std_entropy:
                z = abs(entropy - self.rolling_mean_entropy) / self.rolling_std_entropy
                anomalies['entropy'] = {
                    'is_anomaly': True,
                    'z_score': -z,
                    'value': entropy,
                    'mean': self.rolling_mean_entropy,
                    'std': self.rolling_std_entropy,
                }
                self.is_anomaly_entropy = True
                self.anomaly_score = max(self.anomaly_score, z)

        return anomalies


class WindowAggregator:
    """Aggregates flows over multiple fixed time windows with rolling statistics."""

    def __init__(
        self,
        window_sizes: Optional[List[int]] = None,
        history_size: int = 50,
        enable_rolling_stats: bool = True,
    ) -> None:
        self.window_sizes = window_sizes or [5, 60]
        self.history_size = history_size
        self.enable_rolling_stats = enable_rolling_stats

        self.window_history: Dict[int, deque] = {}
        self.rolling_stats: Dict[int, deque] = {}
        self.current_windows: Dict[str, TimeWindow] = {}
        self._last_flow_counters: Dict[str, Dict[str, int]] = {}
        self._active_bucket_start: Dict[int, float] = {}
        self._last_cleanup = time.time()
        self._max_current_windows = 100

        for size in self.window_sizes:
            self.window_history[size] = deque(maxlen=self.history_size)
            self.rolling_stats[size] = deque(maxlen=self.history_size)

        logger.info(f"WindowAggregator initialised with window sizes: {self.window_sizes}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_window(self, window_size: int, current_time: float) -> TimeWindow:
        """Get or create the active window for the given size and time."""
        window_start = math.floor(current_time / window_size) * window_size
        window_key = f"{window_size}_{window_start}"

        if window_key not in self.current_windows:
            new_window = TimeWindow(
                start_time=window_start,
                end_time=window_start + window_size,
            )
            self.current_windows[window_key] = new_window
            self.window_history[window_size].append(new_window)
            self._cleanup_windows(current_time)

        return self.current_windows[window_key]

    def _cleanup_windows(self, current_time: float) -> None:
        """Evict window entries that expired more than 60 seconds ago."""
        stale = [
            k for k, w in self.current_windows.items()
            if current_time > w.end_time + 60
        ]
        for k in stale:
            del self.current_windows[k]

    def _to_int_counter(self, value: Any) -> int:
        """Safely coerce a value to a non-negative integer counter."""
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def _build_delta_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert cumulative flow snapshots into per-update deltas.

        FlowBuilder emits cumulative counters over the lifetime of a flow.
        Adding those counters directly to a time window would double-count
        every packet that arrived in an earlier window.  This method computes
        the delta since the last time the same flow_id was seen.
        """
        flow_id = flow.get('flow_id')
        if not flow_id:
            # No flow_id → treat as a standalone record, use as-is.
            return dict(flow)

        current = {
            'total_packets': self._to_int_counter(
                flow.get('total_packets', flow.get('packets', 0))
            ),
            'total_bytes': self._to_int_counter(
                flow.get('total_bytes', flow.get('bytes', 0))
            ),
            'tcp_syn_count': self._to_int_counter(flow.get('tcp_syn_count', 0)),
            'tcp_rst_count': self._to_int_counter(flow.get('tcp_rst_count', 0)),
            'tcp_fin_count': self._to_int_counter(flow.get('tcp_fin_count', 0)),
        }
        previous = self._last_flow_counters.get(flow_id)

        # On first appearance or counter reset (e.g. new flow with same ID),
        # take the current values as the delta.
        if previous is None or any(
            current[k] < previous.get(k, 0) for k in current
        ):
            delta = current
        else:
            delta = {k: current[k] - previous.get(k, 0) for k in current}

        self._last_flow_counters[flow_id] = current

        # Nothing new — skip this update.
        if not any(delta.values()):
            return None

        delta_flow = dict(flow)
        delta_flow.update({
            'total_packets': delta['total_packets'],
            'packets': delta['total_packets'],
            'total_bytes': delta['total_bytes'],
            'bytes': delta['total_bytes'],
            'tcp_syn_count': delta['tcp_syn_count'],
            'tcp_rst_count': delta['tcp_rst_count'],
            'tcp_fin_count': delta['tcp_fin_count'],
        })
        return delta_flow

    def _update_rolling_stats(self, window_size: int) -> None:
        """Recompute rolling mean/std for packets-per-second and entropy."""
        if not self.enable_rolling_stats:
            return

        history = self.window_history[window_size]
        if len(history) < 10:
            return

        tail = list(itertools.islice(reversed(history), min(50, len(history))))

        packet_rates = [w.packets_per_second for w in tail]
        entropies = [w.entropy_src_ip for w in tail]

        def _mean_std(values: List[float]):
            n = len(values)
            m = sum(values) / n
            s = math.sqrt(sum((x - m) ** 2 for x in values) / n)
            return m, s

        mean_p, std_p = _mean_std(packet_rates)
        mean_e, std_e = _mean_std(entropies)

        latest = history[-1]
        agg = AggregatedStats(
            timestamp=latest.end_time,
            window_size_seconds=window_size,
            metrics=latest.to_dict(),
            rolling_mean_packets=mean_p,
            rolling_std_packets=std_p,
            rolling_mean_entropy=mean_e,
            rolling_std_entropy=std_e,
        )
        agg.check_anomalies()
        self.rolling_stats[window_size].append(agg)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Add a flow to all windows.

        Returns a safe copy of the aggregated stats when the smallest window
        rolls over, otherwise None.

        FIX BUG-36: The original code returned ``dict(agg_stats.__dict__)``
        which is a *shallow* copy.  The ``metrics`` field is itself a dict, so
        callers could mutate nested structures and corrupt the internal
        rolling_stats deque.  Now we return a deep copy.
        """
        current_time = time.time()
        result: Optional[Dict[str, Any]] = None

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
                        if size == min(self.window_sizes) and result is None:
                            if self.rolling_stats[size]:
                                # FIX BUG-36: deep copy to prevent caller
                                # mutations from corrupting internal state.
                                result = copy.deepcopy(
                                    self.rolling_stats[size][-1].__dict__
                                )
                            else:
                                agg = AggregatedStats(
                                    timestamp=old.end_time,
                                    window_size_seconds=size,
                                    metrics=old.to_dict(),
                                )
                                result = copy.deepcopy(agg.__dict__)

                window = self._get_window(size, current_time)
                window.add_flow(delta_flow)
                self._active_bucket_start[size] = window_start

            if current_time - self._last_cleanup > 60:
                self._cleanup_windows(current_time)
                self._last_cleanup = current_time

            return result

        except Exception as exc:
            logger.error(f"Error adding flow to WindowAggregator: {exc}")
            return None

    def get_current_stats(self) -> Dict[str, Any]:
        """Return the to_dict() of the currently active window per size."""
        stats: Dict[str, Any] = {}
        for size in self.window_sizes:
            prefix = f"{size}_"
            for key, window in self.current_windows.items():
                if key.startswith(prefix):
                    stats[f"window_{size}s"] = window.to_dict()
                    break
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregator meta-statistics."""
        return {
            'window_sizes': self.window_sizes,
            'active_windows': len(self.current_windows),
            'history_size': self.history_size,
            'enabled_rolling_stats': self.enable_rolling_stats,
        }


class RealtimeAggregator:
    """
    Lightweight single-window real-time aggregator.

    FIX BUG-35: When the system clock advances by more than one window_size
    (e.g. after a system sleep or debugger pause), the original code created a
    new window whose end_time was in the past, causing it to roll over
    immediately on the very next call.  Now the new window is always anchored
    to the current wall-clock time when the gap exceeds one window period.
    """

    def __init__(self, window_size_seconds: int = 5) -> None:
        self.window_size = window_size_seconds
        now = time.time()
        self.current_window = TimeWindow(
            start_time=now,
            end_time=now + window_size_seconds,
        )
        self.completed_windows: deque = deque(maxlen=100)

    def add_flow(self, flow: Dict[str, Any]) -> Optional[TimeWindow]:
        """Add a flow and return the completed window if the bucket rolled over."""
        current_time = time.time()

        if current_time >= self.current_window.end_time:
            completed = self.current_window
            self.completed_windows.append(completed)

            # FIX BUG-35: If the gap is larger than one window period (e.g.
            # process was suspended), start the new window from now rather than
            # from the old end_time, which would already be in the past.
            gap = current_time - self.current_window.end_time
            if gap > self.window_size:
                new_start = current_time
            else:
                new_start = self.current_window.end_time

            self.current_window = TimeWindow(
                start_time=new_start,
                end_time=new_start + self.window_size,
            )
            self.current_window.add_flow(flow)
            return completed

        self.current_window.add_flow(flow)
        return None

    def get_packet_rate(self) -> float:
        return self.current_window.packets_per_second

    def get_entropy(self) -> float:
        return self.current_window.entropy_src_ip

    def get_bytes_per_second(self) -> float:
        return self.current_window.bytes_per_second

    def reset(self) -> None:
        """Reset the aggregator, discarding all accumulated data."""
        now = time.time()
        self.current_window = TimeWindow(
            start_time=now,
            end_time=now + self.window_size,
        )
        self.completed_windows.clear()