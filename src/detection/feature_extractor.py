"""
Feature Extraction Module

Extracts statistical features from network flows and time windows
for DDoS detection.
"""

import math
import itertools
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class FeatureConfig:
    """Configuration for feature extraction"""
    max_flows_per_window: int = 10000
    max_unique_ips: int = 1000
    enable_payload_analysis: bool = False
    enable_dns_features: bool = False
    enable_tcp_flags: bool = True
    window_sizes: List[int] = field(default_factory=lambda: [1, 5, 10, 60])
    feature_normalization: bool = True


@dataclass
class FlowFeatures:
    """Features extracted from a single flow"""
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: int = 0
    sport: int = 0
    dport: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    duration: float = 0.0
    interarrival_mean: float = 0.0
    interarrival_std: float = 0.0
    tcp_syn_count: int = 0
    tcp_syn_ack_count: int = 0
    tcp_rst_count: int = 0
    tcp_fin_count: int = 0
    tcp_syn_ratio: float = 0.0
    tcp_window_avg: float = 0.0
    udp_payload_avg: float = 0.0
    icmp_type_count: Dict[int, int] = field(default_factory=dict)
    app_protocol: str = ""

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array for ML models"""
        return np.array([
            self.total_packets, self.total_bytes, self.avg_packet_size,
            self.packets_per_second, self.bytes_per_second, self.duration,
            self.interarrival_mean, self.interarrival_std, self.tcp_syn_ratio,
            self.tcp_window_avg, self.udp_payload_avg,
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'sport': self.sport,
            'dport': self.dport,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'avg_packet_size': self.avg_packet_size,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'duration': self.duration,
            'interarrival_mean': self.interarrival_mean,
            'interarrival_std': self.interarrival_std,
            'tcp_syn_ratio': self.tcp_syn_ratio,
            'tcp_window_avg': self.tcp_window_avg,
            'udp_payload_avg': self.udp_payload_avg,
            'app_protocol': self.app_protocol,
        }


@dataclass
class TrafficFeatures:
    """Aggregated features from time window traffic"""
    timestamp: float
    window_size: int
    total_packets: int = 0
    total_bytes: int = 0
    total_flows: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    flows_per_second: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    entropy_src_ip: float = 0.0
    entropy_dst_ip: float = 0.0
    entropy_src_port: float = 0.0
    entropy_dst_port: float = 0.0
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    other_ratio: float = 0.0
    avg_packet_size: float = 0.0
    packet_size_std: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    syn_ratio: float = 0.0
    rst_ratio: float = 0.0
    fin_ratio: float = 0.0
    top_src_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_dst_ips: List[Tuple[str, int]] = field(default_factory=list)
    is_syn_flood_suspicious: bool = False
    is_udp_flood_suspicious: bool = False
    is_icmp_flood_suspicious: bool = False
    is_http_flood_suspicious: bool = False

    def to_array(self) -> np.ndarray:
        """Convert features to numpy array for ML models"""
        return np.array([
            self.total_packets, self.total_bytes, self.total_flows,
            self.packets_per_second, self.bytes_per_second, self.flows_per_second,
            self.unique_src_ips, self.unique_dst_ips,
            self.entropy_src_ip, self.entropy_dst_ip,
            self.entropy_src_port, self.entropy_dst_port,
            self.tcp_ratio, self.udp_ratio, self.icmp_ratio,
            self.avg_packet_size, self.packet_size_std,
            self.syn_ratio, self.rst_ratio,
            float(self.is_syn_flood_suspicious), float(self.is_udp_flood_suspicious),
            float(self.is_icmp_flood_suspicious), float(self.is_http_flood_suspicious),
        ], dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp,
            'window_size': self.window_size,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'total_flows': self.total_flows,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'flows_per_second': self.flows_per_second,
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'entropy_src_ip': self.entropy_src_ip,
            'entropy_dst_ip': self.entropy_dst_ip,
            'entropy_src_port': self.entropy_src_port,
            'entropy_dst_port': self.entropy_dst_port,
            'tcp_ratio': self.tcp_ratio,
            'udp_ratio': self.udp_ratio,
            'icmp_ratio': self.icmp_ratio,
            'avg_packet_size': self.avg_packet_size,
            'packet_size_std': self.packet_size_std,
            'syn_ratio': self.syn_ratio,
            'rst_ratio': self.rst_ratio,
            'top_src_ips': self.top_src_ips[:10],
            'top_dst_ips': self.top_dst_ips[:10],
            'attack_indicators': {
                'syn_flood': self.is_syn_flood_suspicious,
                'udp_flood': self.is_udp_flood_suspicious,
                'icmp_flood': self.is_icmp_flood_suspicious,
                'http_flood': self.is_http_flood_suspicious,
            },
        }


class FeatureExtractor:
    """Extracts features from network flows and time windows"""
    
    def __init__(self, config: Optional[FeatureConfig] = None):
        self.config = config or FeatureConfig()
        self.feature_history: deque = deque(maxlen=1000)
        self.flow_features_cache: Dict[str, FlowFeatures] = {}
        logger.info(f"FeatureExtractor initialized")

    def extract_flow_features(self, flow_dict: Dict[str, Any]) -> FlowFeatures:
        """Extract features from a flow dictionary"""
        features = FlowFeatures()
        features.flow_id = flow_dict.get('flow_id', '')
        features.src_ip = flow_dict.get('ip_src', '')
        features.dst_ip = flow_dict.get('ip_dst', '')
        features.protocol = flow_dict.get('protocol', 0)
        features.sport = flow_dict.get('sport', 0)
        features.dport = flow_dict.get('dport', 0)
        features.total_packets = flow_dict.get('total_packets', flow_dict.get('packets', 0))
        features.total_bytes = flow_dict.get('total_bytes', flow_dict.get('bytes', 0))

        if features.total_packets > 0:
            features.avg_packet_size = features.total_bytes / features.total_packets

        features.packets_per_second = flow_dict.get('packets_per_sec', 0)
        features.bytes_per_second = flow_dict.get('bytes_per_sec', 0)
        features.duration = flow_dict.get('duration', 0)
        features.interarrival_mean = flow_dict.get('interarrival_mean', 0)
        features.interarrival_std = flow_dict.get('interarrival_std', 0)

        if features.protocol == 6 and self.config.enable_tcp_flags:
            features.tcp_syn_count = flow_dict.get('tcp_syn_count', 0)
            features.tcp_syn_ack_count = flow_dict.get('tcp_syn_ack_count', 0)
            features.tcp_rst_count = flow_dict.get('tcp_rst_count', 0)
            features.tcp_fin_count = flow_dict.get('tcp_fin_count', 0)

            if features.tcp_syn_ack_count > 0:
                features.tcp_syn_ratio = features.tcp_syn_count / features.tcp_syn_ack_count

            features.tcp_window_avg = flow_dict.get('tcp_window_avg', 0)

        if features.protocol == 17:
            features.udp_payload_avg = flow_dict.get('udp_payload_avg', 0)

        features.app_protocol = flow_dict.get('application_protocol', '')

        # Cache the features
        self.flow_features_cache[features.flow_id] = features

        # Limit cache size
        if len(self.flow_features_cache) > self.config.max_flows_per_window:
            evict_n = max(1, int(len(self.flow_features_cache) * 0.2))
            to_remove = list(itertools.islice(self.flow_features_cache.keys(), evict_n))
            for key in to_remove:
                del self.flow_features_cache[key]

        return features

    def extract_traffic_features(self, window_data: Dict[str, Any], window_size: int) -> TrafficFeatures:
        """Extract aggregated features from window data"""
        features = TrafficFeatures(
            timestamp=window_data.get('window_start', datetime.now().timestamp()),
            window_size=window_size,
        )

        features.total_packets = window_data.get('total_packets', 0)
        features.total_bytes = window_data.get('total_bytes', 0)
        flows = window_data.get('flows')
        if isinstance(flows, list):
            features.total_flows = len(flows)
        else:
            features.total_flows = int(window_data.get('flows_count', window_data.get('total_flows', 0)) or 0)

        duration = window_data.get('duration', window_size)
        if duration > 0:
            features.packets_per_second = features.total_packets / duration
            features.bytes_per_second = features.total_bytes / duration
            features.flows_per_second = features.total_flows / duration

        features.unique_src_ips = window_data.get('unique_src_ips', 0)
        features.unique_dst_ips = window_data.get('unique_dst_ips', 0)
        features.entropy_src_ip = window_data.get('entropy_src_ip', 0)
        features.entropy_dst_ip = window_data.get('entropy_dst_ip', 0)

        protocol_counts = window_data.get('protocol_counts') or window_data.get('protocol_distribution', {})
        total_by_proto = sum(protocol_counts.values())
        if total_by_proto > 0:
            features.tcp_ratio = protocol_counts.get(6, 0) / total_by_proto
            features.udp_ratio = protocol_counts.get(17, 0) / total_by_proto
            features.icmp_ratio = protocol_counts.get(1, 0) / total_by_proto
            features.other_ratio = 1 - (features.tcp_ratio + features.udp_ratio + features.icmp_ratio)

        packet_sizes = window_data.get('packet_size_distribution', [])
        if packet_sizes:
            features.avg_packet_size = sum(packet_sizes) / len(packet_sizes)
            features.packet_size_std = float(np.std(packet_sizes)) if len(packet_sizes) > 1 else 0
            features.min_packet_size = min(packet_sizes)
            features.max_packet_size = max(packet_sizes)

        tcp_flags = window_data.get('tcp_flag_counts', {})
        total_tcp = protocol_counts.get(6, 0)
        if total_tcp > 0:
            features.syn_ratio = tcp_flags.get('syn', 0) / total_tcp
            features.rst_ratio = tcp_flags.get('rst', 0) / total_tcp
            features.fin_ratio = tcp_flags.get('fin', 0) / total_tcp

        src_ip_counts = window_data.get('src_ip_counts')
        dst_ip_counts = window_data.get('dst_ip_counts')
        if isinstance(src_ip_counts, dict):
            features.top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        else:
            features.top_src_ips = list(window_data.get('top_src_ips', []))[:20]
        if isinstance(dst_ip_counts, dict):
            features.top_dst_ips = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        else:
            features.top_dst_ips = list(window_data.get('top_dst_ips', []))[:20]

        # Detect flood patterns
        features.is_syn_flood_suspicious = self._detect_syn_flood(features)
        features.is_udp_flood_suspicious = self._detect_udp_flood(features)
        features.is_icmp_flood_suspicious = self._detect_icmp_flood(features)
        features.is_http_flood_suspicious = self._detect_http_flood(window_data)

        self.feature_history.append(features)
        return features

    def _calculate_entropy(self, counter: Dict[Any, int]) -> float:
        """Calculate entropy from a counter dictionary"""
        if not counter:
            return 0.0
        total = sum(counter.values())
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    def _detect_syn_flood(self, features: TrafficFeatures) -> bool:
        """Detect SYN flood indicators"""
        if features.tcp_ratio < 0.5:
            return False
        return (features.syn_ratio > 0.8 and features.unique_src_ips > 100) or \
               (features.syn_ratio > 0.8 and features.packets_per_second > 10000)

    def _detect_udp_flood(self, features: TrafficFeatures) -> bool:
        """Detect UDP flood indicators"""
        if features.udp_ratio < 0.7:
            return False
        return features.udp_ratio > 0.8 and features.packets_per_second > 15000

    def _detect_icmp_flood(self, features: TrafficFeatures) -> bool:
        """Detect ICMP flood indicators"""
        if features.icmp_ratio < 0.5:
            return False
        return features.icmp_ratio > 0.6 and features.packets_per_second > 5000

    def _detect_http_flood(self, window_data: Dict[str, Any]) -> bool:
        """Detect HTTP flood indicators"""
        http_requests = window_data.get('http_request_count', 0)
        duration = window_data.get('duration', 1)
        if duration <= 0:
            return False
        return (http_requests / duration) > 1000

    def get_stats(self) -> Dict[str, Any]:
        """Get feature extractor statistics"""
        return {
            'feature_history_size': len(self.feature_history),
            'flow_cache_size': len(self.flow_features_cache),
        }
